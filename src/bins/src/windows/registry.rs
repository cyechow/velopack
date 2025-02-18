use anyhow::{anyhow, Result};
use chrono::{Datelike, Local as DateTime};
use velopack::locator::VelopackLocator;
use winsafe::{self as w, co, prelude::*};
use std::collections::HashSet;

const UNINSTALL_REGISTRY_KEY: &'static str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall";
const SOFTWARE_CLASSES_REGISTRY_KEY: &'static str = "Software\\Classes";
const SOFTWARE_REGISTERED_APPLICATIONS_KEY: &'static str = "Software\\RegisteredApplications";
const DEFAULT_ICON_KEY: &'static str = "DefaultIcon";
const OPEN_WITH_PROG_KEY: &'static str = "OpenWithProgIds";
// Sub key for setting the command line that the shell invokes
// https://learn.microsoft.com/en-us/windows/win32/com/shell
const SHELL_OPEN_COMMAND_KEY: &'static str = "shell\\open\\command";

fn get_application_capability_path(locator: &VelopackLocator) -> Result<String> {
    let app_title = locator.get_manifest_title();
    let app_authors = locator.get_manifest_authors();
    let capability_path = format!("Software\\{}\\{}\\Capabilities", app_authors, app_title);

    Ok(capability_path.to_string())
}

// Registers as default program: https://learn.microsoft.com/en-us/windows/win32/shell/default-programs#registering-an-application-for-use-with-default-programs
pub fn register_default_program(locator: &VelopackLocator) -> Result<()> {
    // Requires:
    // 1. An "Application Capability" registry subtree
    // 2. A subkey under SOFTWARE/RegisteredApplications that references the above subtree
    let app_title = locator.get_manifest_title();
    let app_capability_path = get_application_capability_path(&locator)?;
    let app_id = locator.get_manifest_id();

    // 1. Create application capability registry subtree
    let reg_app_capability_key = 
        w::HKEY::CURRENT_USER.RegCreateKeyEx(&app_capability_path, None, co::REG_OPTION::NoValue, co::KEY::CREATE_SUB_KEY, None).map_err(|e| anyhow!("Failed to create/open application capability key: {}", e))?.0;
    reg_app_capability_key.RegSetKeyValue(None, Some("ApplicationDescription"), w::RegistryValue::Sz("some description".to_string()))?;
    reg_app_capability_key.RegSetKeyValue(None, Some("ApplicationName"), w::RegistryValue::Sz(app_title))?;

    // 2. Register application subkey - should there be a new app registered for each version??
    let reg_software_registered_apps_key =
        w::HKEY::CURRENT_USER.RegCreateKeyEx(SOFTWARE_REGISTERED_APPLICATIONS_KEY, None, co::REG_OPTION::NoValue, co::KEY::CREATE_SUB_KEY, None).map_err(|e| anyhow!("Failed to create/open software registered applications key: {}", e))?.0;
    // Add to registered applications (for Default Programs)
    reg_software_registered_apps_key.RegSetKeyValue(None, Some(&app_id), w::RegistryValue::Sz(app_capability_path))?;
    Ok(())
}

pub fn unregister_default_program(locator: &VelopackLocator) -> Result<()> {
    // Open registry key to Software/Classes, where the app's custom URL protocols will be stored:
    let reg_software_classes_key =
        w::HKEY::CURRENT_USER.RegCreateKeyEx(SOFTWARE_CLASSES_REGISTRY_KEY, None, co::REG_OPTION::NoValue, co::KEY::CREATE_SUB_KEY, None).map_err(|e| anyhow!("Failed to create/open registry key: {}", e))?.0;
    let app_capability_path = get_application_capability_path(&locator)?;
    reg_software_classes_key.RegDeleteTree(Some(&app_capability_path)).map_err(|e| anyhow!("Failed to delete default program application capabilities subtree: {}", e));
    Ok(())
}

pub fn create_or_update_custom_protocols(next_app: &VelopackLocator, previous_app: Option<&VelopackLocator>) -> Result<()> {
    info!("Writing custom protocol registry keys...");
    let prev_custom_url_protocols = previous_app.map(|a| a.get_custom_url_protocols()).unwrap_or(Vec::<String>::new());
    let next_custom_url_protocols = next_app.get_custom_url_protocols();

    if prev_custom_url_protocols.is_empty() && next_custom_url_protocols.is_empty() {
        return Ok(());
    }
    if prev_custom_url_protocols == next_custom_url_protocols {
        return Ok(());
    }

    let mut removable_protocols = prev_custom_url_protocols;
    let mut new_protocols = next_custom_url_protocols;

    // Do the following only if both are not empty, if one is empty then we're either removing all of one or adding all of one:
    if !removable_protocols.is_empty() && !new_protocols.is_empty() {
        let prev_protocols: HashSet<_> = removable_protocols.into_iter().collect();
        let next_protocols: HashSet<_> = new_protocols.into_iter().collect();

        // Get only the old protocols that needs to be removed from the previous app:
        removable_protocols = prev_protocols.difference(&next_protocols).cloned().collect();
        // Get only the new protocols from the next app that were not part of the previosu app:
        new_protocols = next_protocols.difference(&prev_protocols).cloned().collect();
    }

    // Open registry key to Software/Classes, where the app's custom URL protocols will be stored:
    let reg_software_classes_key =
        w::HKEY::CURRENT_USER.RegCreateKeyEx(SOFTWARE_CLASSES_REGISTRY_KEY, None, co::REG_OPTION::NoValue, co::KEY::CREATE_SUB_KEY, None).map_err(|e| anyhow!("Failed to create/open registry key: {}", e))?.0;
    
    // Remove unused protocols
    let _ = remove_custom_protocols(&reg_software_classes_key, &removable_protocols);

    // Create new protocols
    let _ = register_custom_protocols(next_app, &reg_software_classes_key, &new_protocols);

    Ok(())
}

fn remove_custom_protocols(reg_software_classes_key: &w::HKEY, protocols: &Vec<String>) -> Result<()> {
    if protocols.is_empty() {
        return Ok(());
    }

    for protocol_name in protocols {
        // let reg_protocol_key = reg_software_classes_key.RegCreateKeyEx(&protocol_name, None, co::REG_OPTION::NoValue, co::KEY::ALL_ACCESS, None).map_err(|e| anyhow!("Failed to open key for protocol {}: {}", &protocol_name, e))?;
        // reg_protocol_key.delete_key_recursive().map_err(|e| anyhow!("Failed to recursively delete protocol {}: {}", &protocol_name, e))?;
        reg_software_classes_key.RegDeleteTree(Some(&protocol_name)).map_err(|e| anyhow!("Failed to recursively delete protocol {}: {}", &protocol_name, e))?;
    }
    Ok(())
}

fn register_custom_protocols(locator: &VelopackLocator, reg_software_classes_key: &w::HKEY, new_protocols: &Vec<String>) -> Result<()> {
    if new_protocols.is_empty() {
        return Ok(());
    }

    let main_exe_path = locator.get_main_exe_path_as_string();
    let app_shell_open_cmd = format!("\"{}\" \"%1\"", main_exe_path);

    for protocol_name in new_protocols {
        let _ = register_single_protocol(&reg_software_classes_key, &protocol_name, &app_shell_open_cmd);
    }
    Ok(())
}

fn register_single_protocol(reg_software_classes_key: &w::HKEY, protocol_name: &String, app_shell_open_cmd: &String) -> Result<()> {
    // Create registry key for the protocol
    let reg_protocol_sub_key = reg_software_classes_key.RegCreateKeyEx(&protocol_name, None, co::REG_OPTION::NoValue, co::KEY::ALL_ACCESS, None).map_err(|e| anyhow!("Failed to create subkey for protocol {}: {}", &protocol_name, e))?.0;

    // This seems like standard practice, to add these values for URL protocols.
    reg_protocol_sub_key.RegSetKeyValue(None, Some(""), w::RegistryValue::Sz(format!("URL:{} protocol", &protocol_name)))?;
    reg_protocol_sub_key.RegSetKeyValue(None, Some("URL Protocol"), w::RegistryValue::Sz(String::new()))?;

    // Create registry key for the shell open command
    let reg_protocol_open_sub_key
        = reg_protocol_sub_key.RegCreateKeyEx(SHELL_OPEN_COMMAND_KEY, None, co::REG_OPTION::NoValue, co::KEY::ALL_ACCESS, None).map_err(|e| anyhow!("Failed to create shell open command subkey for protocol {}: {}", &protocol_name, e))?.0;

    // Set value
    reg_protocol_open_sub_key.RegSetKeyValue(None, Some(""), w::RegistryValue::Sz(app_shell_open_cmd.to_string())).map_err(|e| anyhow!("Failed to set shell open command for protocol {}: {}", &protocol_name, e))?;
    Ok(())
}

pub fn remove_all_custom_protocols(locator: &VelopackLocator) -> Result<()> {
    info!("Removing custom protocols registry keys...");
    // Open registry key to Software/Classes, where the app's custom URL protocols will be stored:
    let reg_software_classes_key =
        w::HKEY::CURRENT_USER.RegCreateKeyEx(SOFTWARE_CLASSES_REGISTRY_KEY, None, co::REG_OPTION::NoValue, co::KEY::CREATE_SUB_KEY, None).map_err(|e| anyhow!("Failed to create/open registry key: {}", e))?.0;

    let protocols = locator.get_custom_url_protocols();
    let _ = remove_custom_protocols(&reg_software_classes_key, &protocols);

    Ok(())
}

// Installs a file extension association in accordance with https://learn.microsoft.com/en-us/windows/win32/com/-progid--key
pub fn create_or_update_file_associations(next_app: &VelopackLocator, previous_app: Option<&VelopackLocator>) -> Result<()> {
    info!("Writing file association registry keys...");
    let prev_file_associations = previous_app.map(|a| a.get_file_associations()).unwrap_or(Vec::<String>::new());
    let next_file_associations = next_app.get_file_associations();

    let mut removable_file_associations = prev_file_associations;
    let mut new_file_associations = next_file_associations;

    // Do the following only if both are not empty, if one is empty then we're either removing all of one or adding all of one:
    if !removable_file_associations.is_empty() && !new_file_associations.is_empty() {
        let prev_associations: HashSet<_> = removable_file_associations.into_iter().collect();
        let next_associations: HashSet<_> = new_file_associations.into_iter().collect();

        // Get only the old protocols that needs to be removed from the previous app:
        removable_file_associations = prev_associations.difference(&next_associations).cloned().collect();
        // Get only the new protocols from the next app that were not part of the previosu app:
        new_file_associations = next_associations.difference(&prev_associations).cloned().collect();
    }

    let reg_software_classes_key =
        w::HKEY::CURRENT_USER.RegCreateKeyEx(SOFTWARE_CLASSES_REGISTRY_KEY, None, co::REG_OPTION::NoValue, co::KEY::CREATE_SUB_KEY, None).map_err(|e| anyhow!("Failed to create/open software classes registry key: {}", e))?.0;

    let _ = remove_file_associations(&next_app, &reg_software_classes_key, &removable_file_associations);
    let _ = add_file_associations(&next_app, &reg_software_classes_key, &new_file_associations);

    Ok(())
}

fn add_file_associations(locator: &VelopackLocator, reg_software_classes_key: &w::HKEY, new_file_associations: &Vec<String>) -> Result<()> {
    if new_file_associations.is_empty() {
        return Ok(())
    }

    // Set program ID: https://learn.microsoft.com/en-us/windows/win32/com/-progid--key
    let program_id_file_prefix = format!("{}.File", locator.get_manifest_title());
    let icon_url = locator.get_icon_url();
    let main_exe_path = locator.get_main_exe_path_as_string();

    let app_capability_path = get_application_capability_path(&locator)?;
    let reg_app_capability_key = 
        w::HKEY::CURRENT_USER.RegCreateKeyEx(&app_capability_path, None, co::REG_OPTION::NoValue, co::KEY::CREATE_SUB_KEY, None).map_err(|e| anyhow!("Failed to create/open application capability key: {}", e))?.0;
    let reg_file_assoc_key = reg_app_capability_key.RegCreateKeyEx("FileAssociations", None, co::REG_OPTION::NoValue, co::KEY::ALL_ACCESS, None).map_err(|e| anyhow!("Failed to create subkey for file associations: {}", e))?.0;

    for file_extension in new_file_associations {
        let _ = add_file_association(&reg_software_classes_key, &reg_file_assoc_key, &file_extension, &program_id_file_prefix, &icon_url, &main_exe_path);
    }
    Ok(())
}

// To add file association:
// 1. Add registry subtree with ProgID as name under HKCU/SOFTWARE/Classes with shell/open/command
// 2. Add registry key referencing above subtree under the default program applicaiton capability registration
// See example: https://learn.microsoft.com/en-us/windows/win32/shell/default-programs#full-registration-example
fn add_file_association(reg_software_classes_key: &w::HKEY, reg_file_assoc_key: &w::HKEY, file_extension: &String, program_id_file_prefix: &String, icon_url: &String, app_path: &String) -> Result<()> {
    // Create program id for file extension
    let file_program_id = format!("{}.{}", program_id_file_prefix, file_extension);
    // Register program ID
    let reg_program_key = reg_software_classes_key.RegCreateKeyEx(&file_program_id, None, co::REG_OPTION::NoValue, co::KEY::ALL_ACCESS, None).map_err(|e| anyhow!("Failed to create program subkey for file extension {}: {}", &file_extension, e))?.0;

    // Create registry key for icon to use for files with the extension
    let reg_default_icon_key = reg_program_key.RegCreateKeyEx(DEFAULT_ICON_KEY, None, co::REG_OPTION::NoValue, co::KEY::ALL_ACCESS, None).map_err(|e| anyhow!("Failed to create icon subkey for file extension {}: {}", &file_extension, e))?.0;
    reg_default_icon_key.RegSetKeyValue(None, Some(""), w::RegistryValue::Sz(icon_url.to_string()))?;

    // Create open command registry key
    let _ = register_shell_open_command(&reg_program_key, &app_path);

    // Create registry key for file extension
    let reg_file_extension_key = reg_software_classes_key.RegCreateKeyEx(&file_extension, None, co::REG_OPTION::NoValue, co::KEY::ALL_ACCESS, None).map_err(|e| anyhow!("Failed to create subkey for file extension {}: {}", &file_extension, e))?.0;
    // Clear out existing default program ID: https://github.com/ppy/osu/blob/cf3a379b1cb138e221a5e8749d01bcd584b5db3d/osu.Desktop/Windows/WindowsAssociationManager.cs#L285
    let default_value = reg_file_extension_key.RegGetValue(Some(""), Some(""))?;
    if default_value.reg_type() == co::REG::SZ {
        if default_value.to_string() == file_program_id {
            reg_file_extension_key.RegSetKeyValue(None, Some(""), w::RegistryValue::Sz(String::new()))?;
        }
    }
    // Add to open with dialog: https://learn.microsoft.com/en-us/windows/win32/shell/how-to-include-an-application-on-the-open-with-dialog-box
    let reg_open_with_key = reg_file_extension_key.RegCreateKeyEx(OPEN_WITH_PROG_KEY, None, co::REG_OPTION::NoValue, co::KEY::ALL_ACCESS, None).map_err(|e| anyhow!("Failed to create open with subkey for file extension {}: {}", &file_extension, e))?.0;
    reg_open_with_key.RegSetKeyValue(None, Some(&file_program_id), w::RegistryValue::Sz(String::new()))?;

    // Add to application capabilities subtree (https://learn.microsoft.com/en-us/windows/win32/shell/default-programs#fileassociations):
    let reg_file_assoc_value = format!(".{}", &file_extension);
    let _ = reg_file_assoc_key.RegSetKeyValue(None, Some(&reg_file_assoc_value), w::RegistryValue::Sz(file_program_id));
    Ok(())
}

fn remove_file_associations(locator: &VelopackLocator, reg_software_classes_key: &w::HKEY, removable_file_associations: &Vec<String>) -> Result<()> {
    if removable_file_associations.is_empty() {
        return Ok(())
    }

    let program_id_file_prefix = format!("{}.File", locator.get_manifest_title());
    let app_capability_path = get_application_capability_path(&locator)?;
    let reg_app_capability_key = 
        w::HKEY::CURRENT_USER.RegCreateKeyEx(&app_capability_path, None, co::REG_OPTION::NoValue, co::KEY::CREATE_SUB_KEY, None).map_err(|e| anyhow!("Failed to create/open application capability key: {}", e))?.0;
    let reg_file_assoc_key = reg_app_capability_key.RegCreateKeyEx("FileAssociations", None, co::REG_OPTION::NoValue, co::KEY::ALL_ACCESS, None).map_err(|e| anyhow!("Failed to create subkey for file associations: {}", e))?.0;

    for file_extension in removable_file_associations {
        let file_program_id = format!("{}.{}", program_id_file_prefix.to_string(), file_extension);
        reg_software_classes_key.RegDeleteTree(Some(&file_program_id)).map_err(|e| anyhow!("Failed to recursively delete program ID for extension {}: {}", &file_extension, e))?;
        reg_software_classes_key.RegDeleteTree(Some(&file_extension)).map_err(|e| anyhow!("Failed to recursively delete sub key for extension {}: {}", &file_extension, e))?;
        reg_file_assoc_key.RegDeleteKey(&file_program_id).map_err(|e| anyhow!("Failed to delete app capabilities key for extension {}: {}", &file_extension, e))?;
    }
    Ok(())
}

fn register_shell_open_command(reg_sub_key: &w::HKEY, app_path: &String) -> Result<()> {
    // Create open command registry key
    let reg_open_command_key
        = reg_sub_key.RegCreateKeyEx(SHELL_OPEN_COMMAND_KEY, None, co::REG_OPTION::NoValue, co::KEY::ALL_ACCESS, None).map_err(|e| anyhow!("Failed to create shell open command subkey for app path {}: {}", &app_path, e))?.0;
    // Set open command value value
    let app_shell_open_cmd = format!("\"{}\" \"%1\"", app_path);
    reg_open_command_key.RegSetKeyValue(None, Some(""), w::RegistryValue::Sz(app_shell_open_cmd.to_string())).map_err(|e| anyhow!("Failed to set shell open command app path {}: {}", &app_path, e))?;
    Ok(())
}

pub fun remove_all_file_associations(locator: &VelopackLocator) -> Result<()> {
    // Open registry key to Software/Classes, where the app's custom URL protocols will be stored:
    let reg_software_classes_key =
        w::HKEY::CURRENT_USER.RegCreateKeyEx(SOFTWARE_CLASSES_REGISTRY_KEY, None, co::REG_OPTION::NoValue, co::KEY::CREATE_SUB_KEY, None).map_err(|e| anyhow!("Failed to create/open registry key: {}", e))?.0;
    let app_capability_path = get_application_capability_path(&locator)?;
    reg_software_classes_key.RegDeleteTree(Some(&app_capability_path)).map_err(|e| anyhow!("Failed to delete default program application capabilities subtree: {}", e));

    let file_associations = locator.get_file_associations();
    let _ = remove_file_associations(&locator, &reg_software_classes_key, &file_associations);
    Ok(())
}

pub fn write_uninstall_entry(locator: &VelopackLocator) -> Result<()> {
    info!("Writing uninstall registry key...");

    let app_id = locator.get_manifest_id();
    let app_title = locator.get_manifest_title();
    let app_authors = locator.get_manifest_authors();

    let root_path_str = locator.get_root_dir_as_string();
    let main_exe_path = locator.get_main_exe_path_as_string();
    let updater_path = locator.get_update_path_as_string();

    let folder_size = fs_extra::dir::get_size(locator.get_root_dir()).unwrap_or(0);
    let short_version = locator.get_manifest_version_short_string();

    let now = DateTime::now();
    let formatted_date = format!("{}{:02}{:02}", now.year(), now.month(), now.day());

    let uninstall_cmd = format!("\"{}\" --uninstall", updater_path);
    let uninstall_quiet = format!("\"{}\" --uninstall --silent", updater_path);

    let reg_uninstall =
        w::HKEY::CURRENT_USER.RegCreateKeyEx(UNINSTALL_REGISTRY_KEY, None, co::REG_OPTION::NoValue, co::KEY::CREATE_SUB_KEY, None)?.0;
    let reg_app = reg_uninstall.RegCreateKeyEx(&app_id, None, co::REG_OPTION::NoValue, co::KEY::ALL_ACCESS, None)?.0;
    reg_app.RegSetKeyValue(None, Some("DisplayIcon"), w::RegistryValue::Sz(main_exe_path))?;
    reg_app.RegSetKeyValue(None, Some("DisplayName"), w::RegistryValue::Sz(app_title))?;
    reg_app.RegSetKeyValue(None, Some("DisplayVersion"), w::RegistryValue::Sz(short_version))?;
    reg_app.RegSetKeyValue(None, Some("InstallDate"), w::RegistryValue::Sz(formatted_date))?;
    reg_app.RegSetKeyValue(None, Some("InstallLocation"), w::RegistryValue::Sz(root_path_str))?;
    reg_app.RegSetKeyValue(None, Some("Publisher"), w::RegistryValue::Sz(app_authors))?;
    reg_app.RegSetKeyValue(None, Some("QuietUninstallString"), w::RegistryValue::Sz(uninstall_quiet))?;
    reg_app.RegSetKeyValue(None, Some("UninstallString"), w::RegistryValue::Sz(uninstall_cmd))?;
    reg_app.RegSetKeyValue(None, Some("EstimatedSize"), w::RegistryValue::Dword((folder_size / 1024).try_into()?))?;
    reg_app.RegSetKeyValue(None, Some("NoModify"), w::RegistryValue::Dword(1))?;
    reg_app.RegSetKeyValue(None, Some("NoRepair"), w::RegistryValue::Dword(1))?;
    reg_app.RegSetKeyValue(None, Some("Language"), w::RegistryValue::Dword(0x0409))?;
    Ok(())
}

pub fn remove_uninstall_entry(locator: &VelopackLocator) -> Result<()> {
    info!("Removing uninstall registry keys...");
    let app_id = locator.get_manifest_id();
    let reg_uninstall =
        w::HKEY::CURRENT_USER.RegCreateKeyEx(UNINSTALL_REGISTRY_KEY, None, co::REG_OPTION::NoValue, co::KEY::CREATE_SUB_KEY, None)?.0;
    reg_uninstall.RegDeleteKey(&app_id)?;
    Ok(())
}