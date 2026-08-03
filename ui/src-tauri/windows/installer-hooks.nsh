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

!macro NSIS_HOOK_PREINSTALL
  !insertmacro DifftrailStopProcesses
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  !insertmacro DifftrailStopProcesses
!macroend
