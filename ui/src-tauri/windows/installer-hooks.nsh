; Stop Difftrail processes before NSIS replaces or removes installed resources.
; The desktop shell normally owns the backend, but a crash or forced exit can
; leave the backend orphaned and holding difftrail-backend.exe open.
!macro DifftrailStopProcesses
  ; Stop the tray first so it cannot launch or toggle anything while setup is
  ; handing the installation to the previous uninstaller.
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /IM difftrail-status.exe /T /F'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /IM difftrail-desktop.exe /T /F'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /IM difftrail-backend.exe /T /F'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /IM difftrail-watcher.exe /T /F'
  Pop $0
  Sleep 500
  ; Retry after the desktop process tree has settled. Task termination is
  ; idempotent, and a second pass closes children that were still starting
  ; while the first pass ran.
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /IM difftrail-status.exe /T /F'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /IM difftrail-desktop.exe /T /F'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /IM difftrail-backend.exe /T /F'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /IM difftrail-watcher.exe /T /F'
  Pop $0
  Sleep 500
!macroend

; Tauri invokes the previous uninstaller before NSIS_HOOK_PREINSTALL. Stop a
; running installed copy when the setup UI opens so that older uninstallers can
; remove their binaries instead of returning the generic "Unable to uninstall"
; error. Clean installs do not have the registration and remain untouched.
!define MUI_CUSTOMFUNCTION_GUIINIT DifftrailInstallerGuiInit
Function DifftrailInstallerGuiInit
  ReadRegStr $0 HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\Difftrail" "UninstallString"
  StrCmp $0 "" difftrail_gui_init_done
  !insertmacro DifftrailStopProcesses
  difftrail_gui_init_done:
FunctionEnd

!macro DifftrailInstallStatusIcon
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Difftrail Status" '"$INSTDIR\backend\difftrail-status.exe"'
  CreateShortCut "$SMSTARTUP\Difftrail Status.lnk" "$INSTDIR\backend\difftrail-status.exe"
  Exec '"$INSTDIR\backend\difftrail-status.exe"'
!macroend

!macro DifftrailRemoveStatusIcon
  DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "Difftrail Status"
  Delete "$SMSTARTUP\Difftrail Status.lnk"
!macroend

; The watcher is an opt-in per-user scheduled task. Removing the application
; must remove that executable reference while preserving the local journal.
!macro DifftrailRemoveWatcherTask
  nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /End /TN "Difftrail Watcher"'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\schtasks.exe" /Delete /TN "Difftrail Watcher" /F'
  Pop $0
!macroend

!macro NSIS_HOOK_PREINSTALL
  !insertmacro DifftrailStopProcesses
!macroend

!macro NSIS_HOOK_POSTINSTALL
  !insertmacro DifftrailInstallStatusIcon
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro DifftrailStopProcesses
  !insertmacro DifftrailRemoveStatusIcon
  !insertmacro DifftrailRemoveWatcherTask
!macroend
