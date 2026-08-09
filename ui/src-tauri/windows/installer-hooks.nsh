; Stop Difftrail processes before NSIS replaces or removes installed resources.
; The desktop shell normally owns the backend, but a crash or forced exit can
; leave the backend orphaned and holding difftrail-backend.exe open.
!macro DifftrailStopProcesses
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /IM difftrail-desktop.exe /T /F'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /IM difftrail-backend.exe /T /F'
  Pop $0
  nsExec::ExecToLog '"$SYSDIR\taskkill.exe" /IM difftrail-watcher.exe /T /F'
  Pop $0
  Sleep 1000
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

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro DifftrailStopProcesses
  !insertmacro DifftrailRemoveWatcherTask
!macroend
