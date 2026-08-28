#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::error::Error;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use tauri::Manager;

const API_HOST: &str = "127.0.0.1";
const API_READY_TIMEOUT: Duration = Duration::from_secs(15);
const API_READY_PREFIX: &str = "Difftrail UI API ready on http://127.0.0.1:";
#[cfg(not(debug_assertions))]
const BACKEND_EXECUTABLE: &str = if cfg!(windows) {
    "difftrail-backend.exe"
} else {
    "difftrail-backend"
};

type BackendLog = Arc<Mutex<Vec<String>>>;

struct BackendProcess(Mutex<Option<Child>>);

struct ApiEndpoint {
    port: u16,
    token: String,
}

fn generate_api_token() -> Result<String, Box<dyn Error>> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| {
        io::Error::other(format!("could not generate the local API token: {error}"))
    })?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn database_path() -> PathBuf {
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local_app_data)
            .join("Difftrail")
            .join("difftrail.db");
    }
    PathBuf::from("difftrail.db")
}

#[cfg(not(debug_assertions))]
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
    for ancestor in current.ancestors() {
        if ancestor.join("pyproject.toml").is_file() {
            return Ok(ancestor.to_path_buf());
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

fn parse_api_ready_port(line: &str) -> Option<u16> {
    let port = line.strip_prefix(API_READY_PREFIX)?.trim().parse().ok()?;
    (port != 0).then_some(port)
}

fn capture_api_output<R>(stream: Option<R>) -> (mpsc::Receiver<Result<u16, String>>, BackendLog)
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(1);
    let captured = Arc::new(Mutex::new(Vec::new()));
    let Some(stream) = stream else {
        let _ = sender.send(Err("the backend stdout pipe was unavailable".to_string()));
        return (receiver, captured);
    };

    let captured_lines = Arc::clone(&captured);
    thread::spawn(move || {
        let mut sender = Some(sender);
        for result in BufReader::new(stream).lines() {
            let line = match result {
                Ok(line) => line,
                Err(error) => {
                    if let Some(sender) = sender.take() {
                        let _ = sender.send(Err(format!("could not read backend stdout: {error}")));
                    }
                    break;
                }
            };
            eprintln!("[Difftrail backend stdout] {line}");
            if let Ok(mut lines) = captured_lines.lock() {
                if lines.len() >= 40 {
                    lines.remove(0);
                }
                lines.push(format!("stdout: {line}"));
            }
            if let Some(port) = parse_api_ready_port(&line) {
                if let Some(sender) = sender.take() {
                    let _ = sender.send(Ok(port));
                }
            }
        }
        if let Some(sender) = sender {
            let _ = sender.send(Err(
                "the backend exited without reporting its bound API port".to_string(),
            ));
        }
    });
    (receiver, captured)
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

fn write_startup_failure(
    path: &Path,
    error: &dyn Error,
    primary_log_error: Option<&dyn Error>,
) -> io::Result<()> {
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
        "[{timestamp}] Difftrail backend startup failed:\n{error}"
    )?;
    if let Some(primary_log_error) = primary_log_error {
        writeln!(log, "Primary startup log failure: {primary_log_error}")?;
    }
    writeln!(log)
}

fn record_startup_failure(error: &dyn Error) -> io::Result<()> {
    let path = startup_log_path();
    write_startup_failure(&path, error, None)
}

fn report_startup_failure(error: &dyn Error) {
    let Err(primary_log_error) = record_startup_failure(error) else {
        return;
    };

    let fallback_path = std::env::temp_dir()
        .join("Difftrail")
        .join("startup-errors.log");
    if let Err(fallback_log_error) =
        write_startup_failure(&fallback_path, error, Some(&primary_log_error))
    {
        eprintln!(
            "Difftrail backend startup failed: {error}; primary startup log failed: {primary_log_error}; fallback startup log failed at {}: {fallback_log_error}",
            fallback_path.display()
        );
    }
}

fn api_is_ready(port: u16, token: &str) -> bool {
    let address = format!("{API_HOST}:{port}");
    let Ok(mut stream) = TcpStream::connect_timeout(
        &address.parse().expect("the loopback API address is valid"),
        Duration::from_millis(200),
    ) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    if stream
        .write_all(
            format!(
                "GET /api/health HTTP/1.1\r\nHost: {address}\r\nX-Difftrail-Token: {token}\r\nConnection: close\r\n\r\n"
            )
                .as_bytes(),
        )
        .is_err()
    {
        return false;
    }

    let mut response = Vec::with_capacity(4096);
    let Ok(_) = stream.take(16 * 1024).read_to_end(&mut response) else {
        return false;
    };
    let response = String::from_utf8_lossy(&response);
    let Some((headers, body)) = response.split_once("\r\n\r\n") else {
        return false;
    };
    if !(headers.starts_with("HTTP/1.0 200") || headers.starts_with("HTTP/1.1 200")) {
        return false;
    }
    let compact_body: String = body
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    compact_body.contains(&format!("\"api_port\":{port}"))
}

fn wait_for_api_ready(child: &mut Child, port: u16, token: &str) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + API_READY_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(Box::new(io::Error::other(format!(
                "the backend exited before the API became ready ({status})"
            ))));
        }
        if api_is_ready(port, token) {
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

fn start_local_api(_app: &tauri::AppHandle, token: &str) -> Result<(Child, u16), Box<dyn Error>> {
    let db = database_path();
    let mut command;

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

    #[cfg(not(debug_assertions))]
    {
        let resource_root = workspace_root(_app).map_err(|error| {
            Box::new(io::Error::other(format!(
                "{error}; backend output: no backend output was captured"
            ))) as Box<dyn Error>
        })?;
        let bundled_backend = resource_root.join(BACKEND_EXECUTABLE);
        if !bundled_backend.is_file() {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "the bundled Difftrail backend is missing at {}; backend output: no backend output was captured",
                    bundled_backend.display()
                ),
            )));
        }
        command = Command::new(&bundled_backend);
        command.current_dir(&resource_root);
    }

    command
        .arg("--db")
        .arg(&db)
        .arg("ui")
        .arg("--host")
        .arg(API_HOST)
        .arg("--port")
        .arg("0")
        .env("DIFFTRAIL_API_TOKEN", token)
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
    let (port_receiver, stdout) = capture_api_output(child.stdout.take());
    let stderr = capture_output(child.stderr.take(), "stderr");

    let port = match port_receiver.recv_timeout(API_READY_TIMEOUT) {
        Ok(Ok(port)) => port,
        Ok(Err(message)) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Box::new(io::Error::other(format!(
                "Difftrail backend startup failed: {message}; stdout: {}; stderr: {}",
                backend_output(&stdout),
                backend_output(&stderr)
            ))));
        }
        Err(mpsc::RecvTimeoutError::Timeout) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Box::new(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "Difftrail backend did not report its bound API port within {} seconds; stdout: {}; stderr: {}",
                    API_READY_TIMEOUT.as_secs(),
                    backend_output(&stdout),
                    backend_output(&stderr)
                ),
            )));
        }
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Box::new(io::Error::other(format!(
                "Difftrail backend port channel closed unexpectedly; stdout: {}; stderr: {}",
                backend_output(&stdout),
                backend_output(&stderr)
            ))));
        }
    };

    if let Err(error) = wait_for_api_ready(&mut child, port, token) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Box::new(io::Error::other(format!(
            "Difftrail backend startup failed: {error}; stdout: {}; stderr: {}",
            backend_output(&stdout),
            backend_output(&stderr)
        ))));
    }

    Ok((child, port))
}

#[cfg(test)]
mod tests {
    use super::{capture_api_output, parse_api_ready_port};
    use std::io::Cursor;
    use std::time::Duration;

    #[test]
    fn ready_port_requires_the_exact_backend_banner() {
        assert_eq!(
            parse_api_ready_port("Difftrail UI API ready on http://127.0.0.1:49152"),
            Some(49152)
        );
        assert_eq!(
            parse_api_ready_port("Difftrail UI API ready on http://localhost:49152"),
            None
        );
        assert_eq!(
            parse_api_ready_port("Difftrail UI API ready on http://127.0.0.1:0"),
            None
        );
    }

    #[test]
    fn backend_owned_port_arrives_through_the_private_stdout_pipe() {
        let output = Cursor::new(
            b"startup warning\nDifftrail UI API ready on http://127.0.0.1:49153\n".to_vec(),
        );
        let (receiver, _) = capture_api_output(Some(output));
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            Ok(49153)
        );
    }
}

#[tauri::command]
fn api_port(endpoint: tauri::State<'_, ApiEndpoint>) -> u16 {
    endpoint.port
}

#[tauri::command]
fn api_token(endpoint: tauri::State<'_, ApiEndpoint>) -> String {
    endpoint.token.clone()
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![api_port, api_token])
        .setup(|app| {
            let startup: Result<(Child, u16, String), Box<dyn Error>> = (|| {
                let token = generate_api_token()?;
                let (backend, port) = start_local_api(app.handle(), &token)?;
                Ok((backend, port, token))
            })();
            let (backend, port, token) = startup.inspect_err(|error| {
                report_startup_failure(error.as_ref());
            })?;
            app.manage(ApiEndpoint { port, token });
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
                            let _ = process.wait();
                        }
                    }
                }
            }
        });
}
