#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::error::Error;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tauri::Manager;

const API_HOST: &str = "127.0.0.1";
const API_PORT: u16 = 45917;
const API_READY_TIMEOUT: Duration = Duration::from_secs(15);
const BACKEND_EXECUTABLE: &str = if cfg!(windows) {
    "difftrail-backend.exe"
} else {
    "difftrail-backend"
};

type BackendLog = Arc<Mutex<Vec<String>>>;

struct BackendProcess(Mutex<Option<Child>>);

fn database_path() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local_app_data)
            .join("Difftrail")
            .join("difftrail.db");
    }
    PathBuf::from("difftrail.db")
}

fn workspace_root(app: &tauri::AppHandle) -> Result<PathBuf, Box<dyn Error>> {
    let resource_dir = app.path().resource_dir().map_err(|error| {
        io::Error::other(format!(
            "Could not locate the installed resource directory: {error}"
        ))
    })?;
    Ok(resource_dir.join("backend"))
}

#[cfg(debug_assertions)]
fn source_root() -> Result<PathBuf, io::Error> {
    if let Some(root) = std::env::var_os("DIFFTRAIL_SOURCE_ROOT") {
        return Ok(PathBuf::from(root));
    }

    let current = std::env::current_dir()?;
    if current.join("pyproject.toml").is_file() {
        return Ok(current);
    }
    if let Some(parent) = current.parent() {
        if parent.join("pyproject.toml").is_file() {
            return Ok(parent.to_path_buf());
        }
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "Could not locate the Difftrail source root for development mode; set DIFFTRAIL_SOURCE_ROOT",
    ))
}

fn capture_output<R>(stream: Option<R>, label: &'static str) -> BackendLog
where
    R: Read + Send + 'static,
{
    let captured = Arc::new(Mutex::new(Vec::new()));
    if let Some(stream) = stream {
        let captured_lines = Arc::clone(&captured);
        thread::spawn(move || {
            for line in BufReader::new(stream).lines().map_while(Result::ok) {
                eprintln!("[Difftrail backend {label}] {line}");
                if let Ok(mut lines) = captured_lines.lock() {
                    if lines.len() >= 40 {
                        lines.remove(0);
                    }
                    lines.push(format!("{label}: {line}"));
                }
            }
        });
    }
    captured
}

fn backend_output(logs: &BackendLog) -> String {
    match logs.lock() {
        Ok(lines) if !lines.is_empty() => lines.join(" | "),
        _ => "no backend output was captured".to_string(),
    }
}

fn startup_log_path() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local_app_data)
            .join("Difftrail")
            .join("startup-errors.log");
    }
    PathBuf::from("difftrail-startup-errors.log")
}

fn record_startup_failure(error: &dyn Error) -> io::Result<()> {
    let path = startup_log_path();
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let mut log = OpenOptions::new().create(true).append(true).open(path)?;
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    writeln!(
        log,
        "[{timestamp}] Difftrail backend startup failed:\n{error}\n"
    )
}

fn api_is_ready() -> bool {
    let address = format!("{API_HOST}:{API_PORT}");
    let Ok(mut stream) = TcpStream::connect_timeout(
        &address.parse().expect("the loopback API address is valid"),
        Duration::from_millis(200),
    ) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    if stream
        .write_all(
            format!("GET /api/health HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .is_err()
    {
        return false;
    }

    let mut response = [0_u8; 128];
    let Ok(size) = stream.read(&mut response) else {
        return false;
    };
    let status = String::from_utf8_lossy(&response[..size]);
    status.starts_with("HTTP/1.0 200") || status.starts_with("HTTP/1.1 200")
}

fn wait_for_api_ready(child: &mut Child) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + API_READY_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(Box::new(io::Error::other(format!(
                "the backend exited before the API became ready ({status})"
            ))));
        }
        if api_is_ready() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "the backend did not expose /api/health within {} seconds",
                    API_READY_TIMEOUT.as_secs()
                ),
            )));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn start_local_api(app: &tauri::AppHandle) -> Result<Child, Box<dyn Error>> {
    let db = database_path();
    let resource_root = workspace_root(app).map_err(|error| {
        Box::new(io::Error::other(format!(
            "{error}; backend output: no backend output was captured"
        ))) as Box<dyn Error>
    })?;
    let bundled_backend = resource_root.join(BACKEND_EXECUTABLE);
    let mut command;

    if bundled_backend.is_file() {
        command = Command::new(&bundled_backend);
        command.current_dir(&resource_root);
    } else {
        #[cfg(not(debug_assertions))]
        {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "the bundled Difftrail backend is missing at {}; backend output: no backend output was captured",
                    bundled_backend.display()
                ),
            )));
        }

        #[cfg(debug_assertions)]
        {
            let root = source_root().map_err(|error| {
                Box::new(io::Error::other(format!(
                    "{error}; backend output: no backend output was captured"
                ))) as Box<dyn Error>
            })?;
            let python = std::env::var_os("DIFFTRAIL_PYTHON").unwrap_or_else(|| "python".into());
            command = Command::new(python);
            command.current_dir(root);
            command.arg("-m").arg("difftrail");
        }
    }

    command
        .arg("--db")
        .arg(&db)
        .arg("ui")
        .arg("--host")
        .arg(API_HOST)
        .arg("--port")
        .arg(API_PORT.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }

    let mut child = command.spawn().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "could not start the Difftrail backend process: {error}; backend output: no backend output was captured"
            ),
        )
    })?;
    let stdout = capture_output(child.stdout.take(), "stdout");
    let stderr = capture_output(child.stderr.take(), "stderr");

    if let Err(error) = wait_for_api_ready(&mut child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Box::new(io::Error::other(format!(
            "Difftrail backend startup failed: {error}; stdout: {}; stderr: {}",
            backend_output(&stdout),
            backend_output(&stderr)
        ))));
    }

    Ok(child)
}

fn main() {
    tauri::Builder::default()
        .setup(|app| {
            let backend = start_local_api(app.handle()).map_err(|error| {
                let _ = record_startup_failure(error.as_ref());
                error
            })?;
            app.manage(BackendProcess(Mutex::new(Some(backend))));
            Ok(())
        })
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
