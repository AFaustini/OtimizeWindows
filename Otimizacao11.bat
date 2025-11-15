@rem *** Desabilitar alguns serviços ***

sc stop DiagTrack
sc stop diagnosticshub.standardcollector.service
sc stop dmwappushservice
sc stop RemoteRegistry
sc stop TrkWks
sc stop WMPNetworkSvc
sc stop SysMain
sc stop lmhosts
sc stop VSS
sc stop RemoteAccess
sc stop WSearch
sc stop iphlpsvc
sc stop DoSvc
sc stop SEMgrSvc
sc stop BDESVC
sc stop SstpSvc
sc stop HomeGroupListener
sc stop HomeGroupProvider
sc stop lfsvc
sc stop NetTcpPortSharing
sc stop SharedAccess
sc stop WbioSrvc
sc stop WMPNetworkSvc
sc stop wisvc
sc stop TapiSrv
sc stop SmsRouter
sc stop SharedRealitySvc
sc stop ScDeviceEnum
sc stop SCardSvr
sc stop RetailDemo
sc stop PhoneSvc
sc stop perceptionsimulation
sc stop BTAGService
sc stop AJRouter
sc stop CDPSvc
sc stop ShellHWDetection
sc stop DusmSvc
sc stop BthAvctpSvc
sc stop BITS
sc stop DPS

sc config DiagTrack start= disabled
sc config diagnosticshub.standardcollector.service start= disabled
sc config dmwappushservice start= disabled
sc config RemoteRegistry start= disabled
sc config TrkWks start= disabled
sc config WMPNetworkSvc start= disabled
sc config SysMain start= disabled
sc config lmhosts start= disabled
sc config VSS start= disabled
sc config RemoteAccess start= disabled
sc config WSearch start= disabled
sc config iphlpsvc start= disabled
sc config DoSvc start= disabled
sc config SEMgrSvc start= disabled
sc config BDESVC start= disabled
sc config SstpSvc start= disabled
sc config HomeGroupListener start= disabled
sc config HomeGroupProvider start= disabled
sc config lfsvc start= disabled
sc config NetTcpPortSharing start= disabled
sc config SharedAccess start= disabled
sc config WbioSrvc start= disabled
sc config WMPNetworkSvc start= disabled
sc config wisvc start= disabled
sc config TapiSrv start= disabled
sc config SmsRouter start= disabled
sc config SharedRealitySvc start= disabled
sc config ScDeviceEnum start= disabled
sc config SCardSvr start= disabled
sc config RetailDemo start= disabled
sc config PhoneSvc start= disabled
sc config perceptionsimulation start= disabled
sc config BTAGService start= disabled
sc config AJRouter start= disabled
sc config CDPSvc start= disabled
sc config ShellHWDetection start= disabled
sc config DusmSvc start= disabled
sc config BthAvctpSvc start= disabled
sc config BITS start= demand
sc config DPS start= disabled

REM *** Tweaks de tarefas agendadas ***

schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\SystemRestore\SR" /Disable
schtasks /Change /TN "Microsoft\Office\Office Automatic Updates 2.0" /Disable
schtasks /Change /TN "Microsoft\Office\Office ClickToRun Service Monitor" /Disable
schtasks /Change /TN "Microsoft\Office\Office Feature Updates" /Disable
schtasks /Change /TN "Microsoft\Office\Office Feature Updates Logon" /Disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "MicrosoftEdgeUpdateTaskMachineCore" /Disable
schtasks /Change /TN "MicrosoftEdgeUpdateTaskMachineUA" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
REM schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
REM schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable *** Not sure if should be disabled, maybe related to S.M.A.R.T.
REM schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
REM schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
REM schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable

REM *** Desabilitar Ultimo Acesso Arquivos ***

fsutil.exe behavior set disableLastAccess 1

REM *** Desabilitar nome arquivos 8_3 ***

fsutil.exe 8dot3name set 1

REM *** Desabilitar aplicativos usar meu ID de propaganda ***

reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f

REM *** Desabilitar hibernacao ***

powercfg -h off

REM *** Instalar .NET Framework 3.5 ***

rem Dism /online /norestart /Enable-Feature /FeatureName:"NetFx3"

REM *** Instalar DirectPlay (importante para jogos 2D antigos) ***

Dism /online /norestart /Enable-Feature /FeatureName:"LegacyComponents"
Dism /online /norestart /Enable-Feature /FeatureName:"DirectPlay"

REM *** Instalar VBS (alguns instaladores usam) ***

rem DISM /Online /Add-Capability /CapabilityName:VBSCRIPT~~~~

REM *** Remoção Apps Store ***

rem Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "Get-AppxPackage | where-object {$_.name -notlike '*GamingApp*'} | where-object {$_.name -notlike '*Winget*'} |where-object {$_.name -notlike '*store*'} |  where-object {$_.name -notlike '*DesktopAppInstaller*'} |where-object {$_.name -notlike '*xbox*'} | where-object {$_.name -notlike '*terminal*'} |Remove-AppxPackage"

REM *** Habilitar Printscreen para Snipping Tool ***

REG ADD "HKEY_CURRENT_USER\Control Panel\Keyboard" /v PrintScreenKeyForSnippingEnabled /d 1 /t REG_DWORD /f

REM *** Habilitar Dark Mode ***

REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /d 0 /t REG_DWORD /f
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /d 0 /t REG_DWORD /f

REM *** Configurar Windows Explorer para iniciar no Este Computador, ao invés de Acesso Rápido ***

REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /d 1 /t REG_DWORD /f

REM *** Remover botão Chat da barra de tarefas ***

REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarMn /d 0 /t REG_DWORD /f

REM *** Remover botão busca da barra de tarefas ***

REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Search" /v SearchboxTaskbarMode /d 0 /t REG_DWORD /f

REM *** Habiltar agendamento de aceleração de GPU ***

REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /d 2 /t REG_DWORD /f

REM *** Habiltar modo compacto no Explorador de Arquivos ***

REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v UseCompactMode /d 1 /t REG_DWORD /f

REM *** Desabilitar Widgets ***

rem reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f

REM *** Desabilitar Cores nas Janelas ***

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /v "ColorPrevalence" /t REG_DWORD /d 0 /f

REM *** Desabilitar Cores no Iniciar e Barra de Tarefas ***

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "ColorPrevalence" /t REG_DWORD /d 0 /f

REM *** Desabilitar Bloqueio de Arquivos Baixados na Internet ***

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 1 /f

REM *** Desabilitar Transparencias ***

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 1 /f

REM *** Desabilitar Inicialização rápida ***

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f

REM *** Desabilitar UAC  *** Impacta em programas UWP, como XBOX

rem reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f
rem reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 0 /f
rem reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 0 /f

REM *** Desabilitar Aplicativos em Segundo Plano ***

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d 2 /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /V "LetAppsRunInBackground_UserInControlOfTheseApps" /F
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /V "LetAppsRunInBackground_ForceAllowTheseApps" /F
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /V "LetAppsRunInBackground_ForceDenyTheseApps" /F

REM *** Desabilitar hibernação HD/SSD e demais configs de energia***

ECHO Esquema Balanceado
powercfg -SETACTIVE 381b4222-f694-41f0-9685-ff5bb260df2e
ECHO Marcando configurações na bateria como nunca
powercfg.exe -change -monitor-timeout-dc 5
powercfg.exe -change -standby-timeout-dc 15
powercfg.exe -change -hibernate-timeout-dc 0
ECHO Marcando configurações na tomada como nunca
powercfg.exe -change -monitor-timeout-ac 15
powercfg.exe -change -standby-timeout-ac 0
powercfg.exe -change -hibernate-timeout-ac 0
ECHO Não mexer no brilho do monitor
powercfg -SETDCVALUEINDEX SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 0
powercfg -SETACVALUEINDEX SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 17aaa29b-8b43-4b94-aafe-35f64daaf1ee 0
ECHO Ao fechar a tampa. Na tomada nada e na bateria adormecer
powercfg -SETACVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 0
powercfg -SETDCVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 5ca83367-6e45-459f-a27b-476b1d01c936 3
ECHO Ao apertar o botão de desligar, desligar e não adormecer
powercfg -SETACVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
powercfg -SETDCVALUEINDEX SCHEME_CURRENT 4f971e89-eebd-4455-a8de-9e59040e7347 7648efa3-dd9c-4e3e-b566-50f929386280 3
ECHO Desabilitar hibernação de HD/SSD
powercfg /SETDCVALUEINDEX SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
powercfg /SETACVALUEINDEX SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0

REM *** Melhorar qualidade papel de parede ***

reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 00000064 /f

REM *** Tirar animações inuteís ***

reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v VisualFXSetting /t REG_DWORD /d 2 /f
reg add "HKCU\Control Panel\Desktop" /v UserPreferencesMask /t REG_BINARY /d 90120000010000000000000000 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop\WindowMetrics" /v MinAnimate /t REG_SZ /d 0 /f
rem reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "IconsOnly" /T REG_DWORD /D 1 /F
rem reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ListviewAlphaSelect" /T REG_DWORD /D 1 /F
rem reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "DragFullWindows" /t REG_DWORD /d 0 /f
rem reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d 2 /f
rem reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ListviewShadow" /T REG_DWORD /D 1 /F
rem reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /V "AlwaysHibernateThumbnails" /T REG_DWORD /D 0 /F

REM *** Mostrar arquivos ocultos no Explorer ***

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
 
REM *** Mostrar arquivos super ocultos no Explorer ***

reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

REM *** Desabilitar Armazenamento Reservado ***

DISM /Online /Set-ReservedStorageState /State:Disabled

REM *** Desabilitar Localização ***

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d Deny /f

REM *** Desabilitar acessibilidade de teclado ***

reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d 482 /f
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d 98 /f
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d 34 /f

REM *** Desabilitar Assistência Remota ***

REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /d 0 /t REG_DWORD /f
netsh advfirewall firewall set rule group="Remote Assistance" new enable=no

REM *** Desabilitar Modo de Jogo ***

REG ADD "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AutoGameModeEnabled /d 0 /t REG_DWORD /f

REM *** Desabilitar novo menu de contexto ***

rem reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f

REM *** Desabilitar nova barra do Explorer ***

rem reg add "HKCU\Software\Classes\CLSID\{d93ed569-3b3e-4bff-8355-3c44f6a52bb5}\InprocServer32" /f

REM *** Desabilitar VBS ***

REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /d 0 /t REG_DWORD /f

REM *** Alterar Tamanho de Cache de Icones ***

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d 4096 /f

REM *** Desabilitar Otimizacao de Entrega ***

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v DODownloadMode /d 0 /t REG_DWORD /f

REM *** Desabilitar Mobile Hotspot ***

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v NC_ShowSharedAccessUI /d 0 /t REG_DWORD /f

REM *** Desabilitar conteúdos sugeridos nas configurações ***

REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /d 0 /t REG_DWORD /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /d 0 /t REG_DWORD /f
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /d 0 /t REG_DWORD /f

REM *** Desabilitar propagandas no Explorador de Arquivos ***

REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /d 0 /t REG_DWORD /f

REM *** Desabilitar Dicas e Sugestões ***

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableSoftLanding" /d 1 /t REG_DWORD /f

REM *** Desabilitar busca do bing na pesquisa ***

REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /V BingSearchEnabled /T REG_DWORD /D 0 /F

REM *** Simplificar Configurações Rápidas ***

REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /V SimplifyQuickSettings /T REG_DWORD /D 1 /F

REM *** Desabilitar Configurações Rápidas ***

rem REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Explorer" /V DisableControlCenter /T REG_DWORD /D 1 /F
rem REG ADD "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /V DisableControlCenter /T REG_DWORD /D 1 /F

REM *** Remover Marca Watermark de PC não suportado ***

rem REG ADD "HKEY_CURRENT_USER\Control Panel\UnsupportedHardwareNotificationCache" /V SV1 /T REG_DWORD /D 0 /F
rem REG ADD "HKEY_CURRENT_USER\Control Panel\UnsupportedHardwareNotificationCache" /V SV1 /T REG_DWORD /D 0 /F

REM *** Desabilitar Reabrir apps ao reiniciar ***
rem REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V PersistBrowsers /T REG_DWORD /D 0 /F
rem REG ADD "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /V RestartApps /T REG_DWORD /D 0 /F

REM *** Desabilitar busca web na barra de pesquisa ***
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /V BingSearchEnabled /T REG_DWORD /D 0 /F
REG ADD "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /V DisableSearchBoxSuggestions /T REG_DWORD /D 1 /F

REM *** Desabilitar Power Throttling ***
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Power\PowerThrottling" /V PowerThrottlingOff /T REG_DWORD /D 1 /F

REM *** Otimizar Agendador para Jogos ***
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /V "GPU Priority" /T REG_DWORD /D 8 /F
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /V Priority /T REG_DWORD /D 6 /F
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /V "Scheduling Category" /T REG_SZ /D High /F

REM *** Desabilitar escrita de Cache de navegadores e streaming ***

taskkill /f /im msedge.exe
REM Vivaldi
del /s /q "%userprofile%\AppData\Local\Vivaldi\User Data\Default\Cache"
icacls "%userprofile%\AppData\Local\Vivaldi\User Data\Default\Cache" /deny *S-1-1-0:(F)
REM Google Chrome
del /s /q "%userprofile%\AppData\Local\Google\Chrome\User Data\Default\Cache"
icacls "%userprofile%\AppData\Local\Google\Chrome\User Data\Default\Cache" /deny *S-1-1-0:(F)
REM Opera
del /s /q "%userprofile%\AppData\Local\Opera Software\Opera Stable\Cache"
icacls "%userprofile%\AppData\Local\Opera Software\Opera Stable\Cache" /deny *S-1-1-0:(F)
REM Microsoft Edge
del /s /q "%userprofile%\AppData\Local\Microsoft\Edge\User Data\Default\Cache"
icacls "%userprofile%\AppData\Local\Microsoft\Edge\User Data\Default\Cache" /deny *S-1-1-0:(F)
REM Mozilla Firefox
cd "%userprofile%\AppData\Local\Mozilla\Firefox\Profiles\*default-release"
del /s /q cache2
icacls cache2 /deny *S-1-1-0:(F)
REM Vivaldi Portable
del /s /q "D:Programas\Vivaldi\User Data\Default\Cache"
icacls "D:Programas\Vivaldi\User Data\Default\Cache" /deny *S-1-1-0:(F)
REM Opera Portable
del /s /q "D:\Programas\Opera\profile\data\Cache"
icacls "D:\Programas\Opera\profile\data\Cache" /deny *S-1-1-0:(F)
REM Tidal
del /s /q "%userprofile%\AppData\Roaming\TIDAL\Cache"
icacls "%userprofile%\AppData\Roaming\TIDAL\Cache" /deny *S-1-1-0:(F)
REM Spotify
del /s /q "%LocalAppData%\Spotify\Storage"
icacls "%LocalAppData%\Spotify\Storage" /deny *S-1-1-0:(F)
REM Qobuz
del /s /q "%userprofile%\AppData\Roaming\Qobuz\Cache"
icacls "%userprofile%\AppData\Roaming\Qobuz\Cache" /deny *S-1-1-0:(F)
del /s /q "%userprofile%\AppData\Roaming\Qobuz\tmp\Cache"
icacls "%userprofile%\AppData\Roaming\Qobuz\tmp\Cache" /deny *S-1-1-0:(F)

REM *** Desabilitar Cliente DNS ***
rem reg add "HKLM\SYSTEM\CurrentControlSet\services\Dnscache" /v Start /t REG_DWORD /d 4 /f

REM *** Desabilitar Acompanhamento de Lançamento de Aplicativos ***
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\EdgeUI" /v DisableMFUTracking /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\EdgeUI" /v DisableMFUTracking /t REG_DWORD /d 1 /f

REM *** Desabilitar dicionário pessoal ***
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CPSS\Store\InkingAndTypingPersonalization" /v Value /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\InputPersonalization\TrainedDataStore" /v HarvestContacts /t REG_DWORD /d 0 /f

REM *** Desabilitar frequencia de comentários ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f

REM *** Desabilitar historico de atividades ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f

REM *** Desabilitar historico de pesquisa ***
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SearchSettings" /v IsDeviceSearchHistoryEnabled /t REG_DWORD /d 0 /f

REM *** Desabilitar destaque de pesquisa ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v EnableDynamicContentInWSB /t REG_DWORD /d 0 /f

REM *** Desabilitar comunicação com dispositivos não pareados ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsSyncWithDevices /t REG_DWORD /d 2 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsSyncWithDevices_UserInControlOfTheseApps /t REG_MULTI_SZ  /d 00,00 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsSyncWithDevices_ForceAllowTheseApps /t REG_MULTI_SZ  /d 00,00 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v LetAppsSyncWithDevices_ForceDenyTheseApps /t REG_MULTI_SZ  /d 00,00 /f

REM *** Desabilitar acessos ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\downloadsFolder" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\musicLibrary" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureProgrammatic" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\graphicsCaptureWithoutBorder" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v Value /t REG_SZ /d Deny /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v Value /t REG_SZ /d Deny /f

REM ***Desabilitar Smart App Control***
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy" /v VerifiedAndReputablePolicyState /t REG_DWORD /d 0 /f
REM ***Desabilitar Isolamento de Nucleo***

reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v Enabled /t REG_DWORD /d 0 /f

REM ***Mostrar mais Pins no Iniciar***
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_Layout /t REG_DWORD /d 0 /f

REM ***Desabilitar ID de Anuncio***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f

REM ***Desabilitar Experiencias Compartilhadas***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableCdp /t REG_DWORD /d 0 /f

REM ***Desabilitar Descoberta de Rede e Compartilhamento de Impressoras***
netsh advfirewall firewall set rule group="Network Discovery" new enable=No
netsh advfirewall firewall set rule group="File and Printer Sharing" new enable=No

REM *** Desabilitar memória virtual ***
rem DISM /Online /Add-Capability /CapabilityName:WMIC~~~~
rem wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
rem wmic pagefileset where name="C:\\pagefile.sys" delete

REM ***Desabilitar Pesquisa na nuvem pessoal***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCloudSearch /t REG_DWORD /d 0 /f

REM *** Desabilitar SmartScreen ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableSmartScreen" /T REG_DWORD /D 0 /F
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /V "ShellSmartScreenLevel" /F

REM ***Desabilitar Ações Sugeridas***
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\SmartActionPlatform\SmartClipboard" /v Disabled /t REG_DWORD /d 1 /f

REM ***Desabilitar Stickers no Desktop***
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\current\device\Stickers" /V "EnableStickers" /F

REM ***Desabilitar propagandas na tela de bloqueio**
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "RotatingLockScreenOverlayEnabled" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /V "SubscribedContent-338387Enabled" /T REG_DWORD /D 0 /F

REM ***Desabilitar saiba mais sobre papel de parede do Spotlight**
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" /V "{2cc5ca98-6485-489a-920e-b3e88a6ccce3}" /T REG_DWORD /D 1 /F

REM ***Desabilitar envio de escrita a Microsoft*
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /V "AllowLinguisticDataCollection" /T REG_DWORD /D 0 /F

REM ***Desabilitar Experiencias Personalizadas***
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableTailoredExperiencesWithDiagnosticData" /t REG_DWORD /d 1 /f

REM ***Desabilitar reconhecimento de voz online***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\InputPersonalization" /v "AllowInputPersonalization" /t REG_DWORD /d 0 /f

REM ***Desabilitar auxilios na escrita***
reg add "HKEY_CURRENT_USER\Software\Microsoft\Input\Settings" /v "InsightsEnabled" /t REG_DWORD /d 0 /f

REM ***Aumentar velocidade dos menus***
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d 5 /f

REM *** Desabilitar Criação de Atalho do Edge ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\EdgeUpdate" /v RemoveDesktopShortcutDefault /t REG_DWORD /d 1 /f

REM *** Habilitar prioridades no Update ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v IsContinuousInnovationOptedIn /t REG_DWORD /d 1 /f

REM *** Desabilitar abrir pesquisa ao passar o mouse ***
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Feeds\DSB" /v OpenOnHover /t REG_DWORD /d 0 /f

REM *** Habilitar Finalizar tarefa na barra de tarefas ***
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\DeveloperSettings" /v TaskbarEndTask /t REG_DWORD /d 1 /f

REM *** Esconder extensões de tipos de arquivo conhecidos ***
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 1 /f

REM *** Desabilitar notificações no Menu Iniciar ***
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_AccountNotifications /t REG_DWORD /d 0 /f

REM *** Desabilitar busca em Menu Iniciar e Barra de Tarefas ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PolicyManager\default\Search\DisableSearch" /v value /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v DisableSearch /t REG_DWORD /d 1 /f

REM *** Desabilitar Dicas e Sugestões ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-338389Enabled /t REG_DWORD /d 0 /f

REM *** Desabilitar Propagandas Variadas ***
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\UserProfileEngagement" /v ScoobeSystemSettingEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SubscribedContent-310093Enabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_IrisRecommendations /t REG_DWORD /d 0 /f

REM *** Desabilitar Windows Recall ***

reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" /v DisableAIDataAnalysis /t REG_DWORD /d 1 /f
rem DISM /Online /Disable-Feature /FeatureName:"Recall" /Remove

REM ***Instalar Clientes de Jogos ***
REM winget install EpicGames.EpicGamesLauncher -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install GOG.Galaxy -h -s winget --accept-source-agreements --accept-package-agreements
REM winget install ElectronicArts.EADesktop -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Valve.Steam -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Ubisoft.Connect -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Amazon.Games -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Playnite.Playnite -s winget -h --accept-source-agreements --accept-package-agreements

REM ***Instalar Frameworks ***

REM winget install Microsoft.DotNet.DesktopRuntime.3_1 -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Microsoft.DotNet.DesktopRuntime.5 -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Microsoft.DotNet.DesktopRuntime.6 -s winget -h --accept-source-agreements --accept-package-agreements

REM ***Instalar Emuladores***
REM cinst cemu -y
REM winget install DolphinEmu.DolphinEmu -s winget -h --accept-source-agreements --accept-package-agreements
REM cinst fs-uae -y
REM cinst mame -y
REM cinst nestopia -y
REM winget install PPSSPPTeam.PPSSPP -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Libretro.RetroArch -s winget -h --accept-source-agreements --accept-package-agreements
REM cinst snes9x -y
REM cinst visualboyadvance -y
REM cinst winvice -y

REM ***Instalar Drivers***
REM cinst intel-chipset-device-software -y
REM cinst intel-graphics-driver -y
REM cinst intel-rst-driver -y
REM cinst nvidia-display-driver -y
REM cinst realtek-s winget -h --accept-source-agreements --accept-package-agreementsd-audio-driver -y
REM winget install AMD.RyzenMaster -s winget -h --accept-source-agreements --accept-package-agreements

REM ***Instalar Navegadores e Programas para Internet***
REM winget install eloston.ungoogled-chromium -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Dropbox.Dropbox -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install KDE.Falkon -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Mozilla.Firefox -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Opera.Opera -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install PicoTorrent.PicoTorrent -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install VivaldiTechnologies.Vivaldi -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Microsoft.OneDrive -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install TIDALMusicAS.TIDAL -s winget -h --accept-source-agreements --accept-package-agreements

REM ***Instalar Aplicativos***
rem winget install Files-Community.Files -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install calibre.calibre -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install PeterPawlowski.foobar2000 -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install IrfanSkiljan.IrfanView -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install XBMCFoundation.Kodi -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install CodeJelly.Launchy -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install LibreOffice.LibreOffice -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install MacType.MacType -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Henry++.MemReduct -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install MKVToolNix.MKVToolNix -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install clsid2.mpc -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install 9PD88QB3BGKN -s msstore -h --accept-source-agreements --accept-package-agreements & rem mpc-be
REM cinst msiafterburner -y
REM winget install Notepad++.Notepad++ -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Microsoft.Office -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install 9WZDNCRFHVN5 -s msstore -h --accept-source-agreements --accept-package-agreements & rem Calculadora
REM cinst oldcalc -y
REM cinst openal -y
REM winget install 9NBHCS1LX4R0 -s msstore -h --accept-source-agreements --accept-package-agreements & rem paint.net
REM winget install QL-Win.QuickLook -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install QuiteRSS.QuiteRSS -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install PunkLabs.RocketDock -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Piriform.Speccy -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install SumatraPDF.SumatraPDF -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install RandomEngy.VidCoder -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install VideoLAN.VLC -s winget -h --accept-source-agreements --accept-package-agreements
REM cinst windowblinds -y
REM winget install Microsoft.winfile -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install 9NBLGGH404XM -s msstore -h --accept-source-agreements --accept-package-agreements & rem xplorer² lite
REM winget install ModernFlyouts.ModernFlyouts -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Files-Community.Files -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Open-Shell.Open-Shell-Menu -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install t1m0thyj.WinDynamicDesktop -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install File-New-Project.EarTrumpet -s winget -h --accept-source-agreements --accept-package-agreements

REM ***Instalar Utilitários***
REM winget install 7zip.7zip -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install 7zip.7zipAlpha -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install BleachBit.BleachBit -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Piriform.CCleaner -s winget -h --accept-source-agreements --accept-package-agreements
REM cinst compactgui -y
REM winget install CPUID.CPU-Z -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Piriform.Defraggler -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Microsoft.DirectX -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install ESET.Nod32 -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install ESET.Security -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install flux.flux -s winget -h --accept-source-agreements --accept-package-agreements
REM cinst kis -y
REM winget install TechPowerUp.GPU-Z -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install REALiX.HWiNFO -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Microsoft.PowerToys -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Rainmeter.Rainmeter -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Piriform.Recuva -s winget -h --accept-source-agreements --accept-package-agreements
REM cinst regscanner -y
REM winget install den4b.ReNamer -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install AntibodySoftware.WizTree -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Microsoft.WindowsTerminal -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install Lexikos.AutoHotkey -s winget -h --accept-source-agreements --accept-package-agreements
REM winget install CodeSector.TeraCopy -s winget -h --accept-source-agreements --accept-package-agreements

rem REG DELETE "HKCU\Control Panel\Quick Actions" /F
TIMEOUT /T 5
taskkill /f /im explorer.exe
start explorer.exe
msg %username% Otimizacao Finalizada com Sucesso
