use std::fs;
use std::path::PathBuf;
use tauri::Manager;

// All vault file I/O goes through these two commands (plain std::fs), so the app's
// entire disk surface is auditable right here. We deliberately do NOT use the fs
// plugin or grant a filesystem scope: the path always originates from a native file
// dialog the user drives, and nothing else can be read or written.
#[tauri::command]
fn read_vault(path: String) -> Result<String, String> {
    fs::read_to_string(&path).map_err(|e| e.to_string())
}

#[tauri::command]
fn write_vault(path: String, contents: String) -> Result<(), String> {
    fs::write(&path, contents).map_err(|e| e.to_string())
}

// The recent-vaults list (paths only, never contents) lives in the OS app-config
// dir. It is the single piece of OS-level state the app keeps, and the UI can clear
// it.
fn recents_file(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let dir = app.path().app_config_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir.join("recents.json"))
}

#[tauri::command]
fn read_recents(app: tauri::AppHandle) -> Result<String, String> {
    let path = recents_file(&app)?;
    Ok(fs::read_to_string(&path).unwrap_or_else(|_| "[]".to_string()))
}

#[tauri::command]
fn write_recents(app: tauri::AppHandle, contents: String) -> Result<(), String> {
    let path = recents_file(&app)?;
    fs::write(&path, contents).map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            read_vault,
            write_vault,
            read_recents,
            write_recents
        ])
        .run(tauri::generate_context!())
        .expect("error while running passwd desktop");
}
