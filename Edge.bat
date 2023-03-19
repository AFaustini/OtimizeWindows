REM *** Remover botão Bing e Sidebar ***

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v HubsSidebarEnabled /d 0 /t REG_DWORD /f

REM *** Remover Edge em Segundo Plano ***

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v BackgroundModeEnabled /d 0 /t REG_DWORD /f

REM *** Remover Edge abrir ao iniciar ***

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v StartupBoostEnabled /d 0 /t REG_DWORD /f

REM *** Habilitar modo de eficiência ***

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v EfficiencyMode /d 0 /t REG_DWORD /f

REM *** Remover Botao Acrobat ***

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v ShowAcrobatSubscriptionButton /d 0 /t REG_DWORD /f

REM *** Desabilitar algumas permissões ***

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v VideoCaptureAllowed /d 0 /t REG_DWORD /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v DefaultGeolocationSetting /d 2 /t REG_DWORD /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v AudioCaptureAllowed /d 0 /t REG_DWORD /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v DefaultSensorsSetting /d 2 /t REG_DWORD /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Edge" /v DefaultNotificationsSetting /d 2 /t REG_DWORD /f
