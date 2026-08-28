#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
mod windows_app {
    use std::error::Error;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::thread;
    use std::time::{Duration, SystemTime};

    use image::ImageReader;
    use tao::event::Event;
    use tao::event_loop::{ControlFlow, EventLoopBuilder};
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
    use windows_sys::Win32::System::Threading::CreateMutexW;

    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    const STATUS_ID: &str = "toggle-background-collection";
    const OPEN_ID: &str = "open-difftrail";
    const EXIT_ID: &str = "exit-difftrail-status";
    const ACTIVE_MARKER: &str = "watcher.active";
    const TASK_NAME: &str = "Difftrail Watcher";
    const STATUS_INTERVAL: Duration = Duration::from_secs(2);
    const STALE_ACTIVE_MARKER: Duration = Duration::from_secs(120);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CollectionStatus {
        Scanning,
        Enabled,
        Off,
    }

    impl CollectionStatus {
        fn menu_text(self) -> &'static str {
            match self {
                Self::Scanning => "Background collection: scanning now",
                Self::Enabled => "Background collection: enabled",
                Self::Off => "Background collection: off",
            }
        }

        fn tooltip(self) -> &'static str {
            match self {
                Self::Scanning => "Difftrail — background scan in progress",
                Self::Enabled => "Difftrail — background collection enabled",
                Self::Off => "Difftrail — background collection is off",
            }
        }
    }

    #[derive(Debug)]
    enum UserEvent {
        Tray(TrayIconEvent),
        Menu(MenuEvent),
        Refresh,
    }

    struct InstanceGuard(HANDLE);

    impl InstanceGuard {
        fn acquire() -> Result<Option<Self>, Box<dyn Error>> {
            let name: Vec<u16> = OsStr::new("Local\\DifftrailStatusIcon")
                .encode_wide()
                .chain(Some(0))
                .collect();
            let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
            if handle.is_null() {
                return Err(Box::new(std::io::Error::last_os_error()));
            }
            if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
                unsafe {
                    CloseHandle(handle);
                }
                return Ok(None);
            }
            Ok(Some(Self(handle)))
        }
    }

    impl Drop for InstanceGuard {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn install_root() -> PathBuf {
        std::env::current_exe()
            .ok()
            .and_then(|path| path.parent().and_then(Path::parent).map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."))
    }

    fn watcher_is_active(root: &Path) -> bool {
        let marker = root.join(ACTIVE_MARKER);
        marker
            .metadata()
            .and_then(|metadata| metadata.modified())
            .and_then(|modified| {
                SystemTime::now()
                    .duration_since(modified)
                    .map_err(std::io::Error::other)
            })
            .is_ok_and(|age| age <= STALE_ACTIVE_MARKER)
    }

    fn watcher_is_enabled() -> bool {
        let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let schtasks = PathBuf::from(system_root)
            .join("System32")
            .join("schtasks.exe");
        Command::new(schtasks)
            .args(["/Query", "/TN", TASK_NAME])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn powershell_executable() -> PathBuf {
        let system_root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        PathBuf::from(system_root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe")
    }

    fn run_watcher_script(
        root: &Path,
        script_name: &str,
        extra_arguments: &[(&str, String)],
    ) -> bool {
        let script = root.join("backend").join(script_name);
        if !script.is_file() {
            return false;
        }

        let mut command = Command::new(powershell_executable());
        command
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(script)
            .current_dir(root.join("backend"));
        for (name, value) in extra_arguments {
            command.arg(name).arg(value);
        }
        command
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }

    fn database_path(root: &Path) -> PathBuf {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .map(|path| path.join("Difftrail").join("difftrail.db"))
            .unwrap_or_else(|| root.join("difftrail.db"))
    }

    fn enable_watcher(root: &Path) -> bool {
        let watcher = root.join("backend").join("difftrail-watcher.exe");
        let working_directory = root.join("backend");
        run_watcher_script(
            root,
            "install-watcher.ps1",
            &[
                ("-IntervalSeconds", "300".to_string()),
                ("-DatabasePath", database_path(root).display().to_string()),
                ("-ExecutablePath", watcher.display().to_string()),
                ("-WorkingDirectory", working_directory.display().to_string()),
            ],
        )
    }

    fn disable_watcher(root: &Path) -> bool {
        run_watcher_script(root, "uninstall-watcher.ps1", &[])
    }

    fn toggle_watcher(root: &Path) {
        match collection_status(root) {
            CollectionStatus::Off => {
                let _ = enable_watcher(root);
            }
            CollectionStatus::Enabled | CollectionStatus::Scanning => {
                let _ = disable_watcher(root);
            }
        }
    }

    fn collection_status(root: &Path) -> CollectionStatus {
        if watcher_is_active(root) {
            CollectionStatus::Scanning
        } else if watcher_is_enabled() {
            CollectionStatus::Enabled
        } else {
            CollectionStatus::Off
        }
    }

    fn open_difftrail(root: &Path) {
        let executable = root.join("difftrail-desktop.exe");
        if executable.is_file() {
            let _ = Command::new(executable)
                .creation_flags(CREATE_NO_WINDOW)
                .spawn();
        }
    }

    fn load_icon() -> Result<Icon, Box<dyn Error>> {
        let image = ImageReader::new(std::io::Cursor::new(include_bytes!(
            "../../icons/32x32.png"
        )))
        .with_guessed_format()?
        .decode()?
        .into_rgba8();
        let (width, height) = image.dimensions();
        Ok(Icon::from_rgba(image.into_raw(), width, height)?)
    }

    pub fn run() -> Result<(), Box<dyn Error>> {
        let Some(_instance_guard) = InstanceGuard::acquire()? else {
            return Ok(());
        };

        let root = install_root();
        let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
        let proxy = event_loop.create_proxy();
        TrayIconEvent::set_event_handler(Some(move |event| {
            let _ = proxy.send_event(UserEvent::Tray(event));
        }));
        let proxy = event_loop.create_proxy();
        MenuEvent::set_event_handler(Some(move |event| {
            let _ = proxy.send_event(UserEvent::Menu(event));
        }));
        let proxy = event_loop.create_proxy();
        thread::spawn(move || loop {
            thread::sleep(STATUS_INTERVAL);
            if proxy.send_event(UserEvent::Refresh).is_err() {
                break;
            }
        });

        let initial_status = collection_status(&root);
        let status_item = MenuItem::with_id(STATUS_ID, initial_status.menu_text(), true, None);
        let open_item = MenuItem::with_id(OPEN_ID, "Open Difftrail", true, None);
        let exit_item = MenuItem::with_id(EXIT_ID, "Exit Difftrail", true, None);
        let separator = PredefinedMenuItem::separator();
        let menu = Menu::with_items(&[&status_item, &separator, &open_item, &exit_item])?;
        let tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_menu_on_left_click(false)
            .with_tooltip(initial_status.tooltip())
            .with_icon(load_icon()?)
            .build()?;

        let mut last_status = initial_status;
        event_loop.run(move |event, _, control_flow| {
            *control_flow = ControlFlow::Wait;
            match event {
                Event::UserEvent(UserEvent::Tray(
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
                    | TrayIconEvent::DoubleClick {
                        button: MouseButton::Left,
                        ..
                    },
                )) => open_difftrail(&root),
                Event::UserEvent(UserEvent::Menu(event)) if event.id.as_ref() == STATUS_ID => {
                    toggle_watcher(&root);
                    let status = collection_status(&root);
                    if status != last_status {
                        status_item.set_text(status.menu_text());
                        let _ = tray.set_tooltip(Some(status.tooltip()));
                        last_status = status;
                    }
                }
                Event::UserEvent(UserEvent::Menu(event)) if event.id.as_ref() == OPEN_ID => {
                    open_difftrail(&root);
                }
                Event::UserEvent(UserEvent::Menu(event)) if event.id.as_ref() == EXIT_ID => {
                    *control_flow = ControlFlow::Exit;
                }
                Event::UserEvent(UserEvent::Refresh) => {
                    let status = collection_status(&root);
                    if status != last_status {
                        status_item.set_text(status.menu_text());
                        let _ = tray.set_tooltip(Some(status.tooltip()));
                        last_status = status;
                    }
                }
                _ => {}
            }
        });
    }

    #[cfg(test)]
    mod tests {
        use super::CollectionStatus;

        #[test]
        fn status_copy_distinguishes_scanning_enabled_and_off() {
            assert_eq!(
                CollectionStatus::Scanning.menu_text(),
                "Background collection: scanning now"
            );
            assert_eq!(
                CollectionStatus::Enabled.tooltip(),
                "Difftrail — background collection enabled"
            );
            assert_eq!(
                CollectionStatus::Off.tooltip(),
                "Difftrail — background collection is off"
            );
        }
    }
}

#[cfg(windows)]
fn main() {
    let _ = windows_app::run();
}
