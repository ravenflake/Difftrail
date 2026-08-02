#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use tauri::Manager;

struct BackendProcess(Mutex<Option<Child>>);

fn database_path() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local_app_data).join("Difftrail").join("difftrail.db");
    }
    PathBuf::from("difftrail.db")
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn start_local_api() -> Option<Child> {
    let root = workspace_root();
    let db = database_path();
    let python = std::env::var_os("DIFFTRAIL_PYTHON").unwrap_or_else(|| "python".into());
    let mut command = Command::new(python);
    command
        .current_dir(root)
        .args([
            "-m",
            "difftrail",
            "--db",
            db.to_string_lossy().as_ref(),
            "ui",
            "--host",
            "127.0.0.1",
            "--port",
            "45917",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.spawn().ok()
}

fn main() {
    let backend = start_local_api();
    tauri::Builder::default()
        .manage(BackendProcess(Mutex::new(backend)))
        .build(tauri::generate_context!())
        .expect("error while building Difftrail")
        .run(|app_handle, event| {
            if let tauri::RunEvent::Exit = event {
                if let Some(process) = app_handle.try_state::<BackendProcess>() {
                    if let Ok(mut child) = process.0.lock() {
                        if let Some(process) = child.as_mut() {
                            let _ = process.kill();
                        }
                    }
                }
            }
        });
}
