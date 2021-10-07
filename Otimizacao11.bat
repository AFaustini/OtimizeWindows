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

REM Desabilitar aplicativos usar meu ID de propaganda
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f

REM *** Desabilitar hibernacao ***
powercfg -h off 

REM *** Instalar .NET Framework 3.5 ***
Dism /online /norestart /Enable-Feature /FeatureName:"NetFx3"

REM *** Remover Features Não Usadas ***
DISM.exe /Online /norestart /Disable-Feature /featurename:SimpleTCP /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:Windows-Identity-Foundation /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:DirectoryServices-ADAM-Client /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WebServerRole /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WebServer /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-CommonHttpFeatures /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HttpErrors /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HttpRedirect /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ApplicationDevelopment /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-NetFxExtensibility /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-NetFxExtensibility45 /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HealthAndDiagnostics /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HttpLogging /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-LoggingLibraries /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-RequestMonitor /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HttpTracing /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-Security /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-URLAuthorization /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-RequestFiltering /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-IPSecurity /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-Performance /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HttpCompressionDynamic /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WebServerManagementTools /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ManagementScriptingTools /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-IIS6ManagementCompatibility /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-Metabase /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WAS-WindowsActivationService /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WAS-ProcessModel /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WAS-NetFxEnvironment /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WAS-ConfigurationAPI /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HostableWebCore /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-CertProvider /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WindowsAuthentication /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-DigestAuthentication /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ClientCertificateMappingAuthentication /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-IISCertificateMappingAuthentication /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ODBCLogging /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-StaticContent /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-DefaultDocument /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-DirectoryBrowsing /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WebDAV /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WebSockets /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ApplicationInit /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ASPNET /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ASPNET45 /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ASP /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-CGI /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ISAPIExtensions /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ISAPIFilter /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ServerSideIncludes /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-CustomLogging /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-BasicAuthentication /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-HttpCompressionStatic /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ManagementConsole /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-ManagementService /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-WMICompatibility /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-LegacyScripts /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-LegacySnapIn /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-FTPServer /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-FTPSvc /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:IIS-FTPExtensibility /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-Container /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-Server /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-Triggers /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-ADIntegration /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-HTTP /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-Multicast /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:MSMQ-DCOMProxy /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-HTTP-Activation45 /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-TCP-Activation45 /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-Pipe-Activation45 /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-MSMQ-Activation45 /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-HTTP-Activation /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-NonHTTP-Activation /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:NetFx4Extended-ASPNET45 /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:MediaPlayback /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WindowsMediaPlayer /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:Printing-XPSServices-Features /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:MSRDC-Infrastructure /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:TelnetClient /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:TFTP /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:TIFFIFilter /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WorkFolders-Client /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:SMB1Protocol /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:Microsoft-Hyper-V-All /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:Microsoft-Hyper-V-Tools-All /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:Microsoft-Hyper-V /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:Microsoft-Hyper-V-Management-Clients /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:Microsoft-Hyper-V-Management-PowerShell /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:SearchEngine-Client-Package /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WCF-TCP-PortSharing45 /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:SmbDirect /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:Printing-Foundation-Features /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:Printing-Foundation-InternetPrinting-Client /Remove

REM *** Desinstalar apps padrão ***

winget uninstall Microsoft.BingNews_8wekyb3d8bbwe -h
winget uninstall Microsoft.BingWeather_8wekyb3d8bbwe -h
winget uninstall Microsoft.GetHelp_8wekyb3d8bbwe -h
winget uninstall Microsoft.Getstarted_8wekyb3d8bbwe -h
winget uninstall Microsoft.MicrosoftOfficeHub_8wekyb3d8bbwe -h
winget uninstall Microsoft.MicrosoftSolitaireCollection_8wekyb3d8bbwe -h
winget uninstall Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe -h
winget uninstall Microsoft.People_8wekyb3d8bbwe -h
winget uninstall Microsoft.WindowsAlarms_8wekyb3d8bbwe -h
winget uninstall Microsoft.WindowsCamera_8wekyb3d8bbwe -h
winget uninstall Microsoft.WindowsMaps_8wekyb3d8bbwe -h
winget uninstall Microsoft.WindowsSoundRecorder_8wekyb3d8bbwe -h
winget uninstall Microsoft.YourPhone_8wekyb3d8bbwe -h
winget uninstall Microsoft.ZuneMusic_8wekyb3d8bbwe -h
winget uninstall Microsoft.ZuneVideo_8wekyb3d8bbwe -h
winget uninstall microsoft.windowscommunicationsapps_8wekyb3d8bbwe -h
winget uninstall Microsoft.Paint_8wekyb3d8bbwe -h
winget uninstall Microsoft.549981C3F5F10_8wekyb3d8bbwe -h
winget uninstall MicrosoftTeams_8wekyb3d8bbwe -h
rem winget uninstall Microsoft.Windows.Photos_8wekyb3d8bbwe -h
rem winget uninstall Microsoft.WindowsFeedbackHub_8wekyb3d8bbwe -h
rem winget uninstall Microsoft.PowerAutomateDesktop_8wekyb3d8bbwe -h
rem winget uninstall Microsoft.ScreenSketch_8wekyb3d8bbwe -h
rem winget uninstall Microsoft.OneDrive -h

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

REM *** Desabilitar Apps em Segundo Plano ***

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v "LetAppsRunInBackground" /t REG_DWORD /d 2 /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v "LetAppsRunInBackground_UserInControlOfTheseApps" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v "LetAppsRunInBackground_ForceAllowTheseApp" /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v "LetAppsRunInBackground_ForceDenyTheseApp" /f

REM *** Desabilitar Widgets ***

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f

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

REM *** Desabilitar UAC  ***

reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 0 /f

REM *** Desabilitar Aplicativos em Segundo Plano ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d 2 /f
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /V "LetAppsRunInBackground_UserInControlOfTheseApps" /F
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /V "LetAppsRunInBackground_ForceAllowTheseApps" /F
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /V "LetAppsRunInBackground_ForceDenyTheseApps" /F

REM *** Desabilitar hibernação HD/SSD e demais configs de energia***
ECHO Esquema Balanceado
powercfg -SETACTIVE 381b4222-f694-41f0-9685-ff5bb260df2e
ECHO Esquema Balanceado Ryzen
rem powercfg -SETACTIVE 9897998c-92de-4669-853f-b7cd3ecb2790
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
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 00000100 /f

REM *** Tirar animações inuteís ***
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d 9032078010000000 /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" REG_SZ /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "IconsOnly" /T REG_DWORD /D 1 /F
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ListviewAlphaSelect" /T REG_DWORD /D 1 /F
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "DragFullWindows" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ListviewShadow" /T REG_DWORD /D 1 /F
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /V "AlwaysHibernateThumbnails" /T REG_DWORD /D 0 /F

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

REM *** Desabilitar Modo de Jogo ***
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /v AutoGameModeEnabled /d 0 /t REG_DWORD /f

REM *** Desabilitar novo menu de contexto ***
rem reg add "HKCU\Software\Classes\CLSID\{86ca1aa0-34aa-4e8b-a509-50c905bae2a2}\InprocServer32" /f /ve

REM *** Desabilitar nova barra do Explorer ***
rem reg add "HKCU\Software\Classes\CLSID\{d93ed569-3b3e-4bff-8355-3c44f6a52bb5}\InprocServer32" /f /ve

REM *** Desabilitar VBS ***
REG ADD "HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\DeviceGuard" /v EnableVirtualizationBasedSecurity /d 0 /t REG_DWORD /f

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

REM ***Instalar Clientes de Jogos ***
REM winget install EpicGames.EpicGamesLauncher -h
REM winget install GOG.Galaxy -h
REM winget install ElectronicArts.EADesktop -h
REM winget install Valve.Steam -h
REM winget install Ubisoft.Connect -h
REM winget install Twitch.Twitch -h
REM winget install Playnite.Playnite -h

REM ***Instalar Frameworks ***

winget install Microsoft.dotnetRuntime.3-x64 -h
winget install Microsoft.dotnetRuntime.5-x64 -h

REM ***Instalar Emuladores***
REM cinst cemu -y
REM winget install DolphinEmu.DolphinEmu -h
REM cinst fs-uae -y
REM cinst mame -y
REM cinst nestopia -y
REM winget install PPSSPPTeam.PPSSPP -h
REM winget install Libretro.RetroArch -h
REM cinst snes9x -y
REM cinst visualboyadvance -y
REM cinst winvice -y

REM ***Instalar Drivers***
REM cinst intel-chipset-device-software -y
REM cinst intel-graphics-driver -y
REM cinst intel-rst-driver -y
REM cinst nvidia-display-driver -y
REM cinst realtek-hd-audio-driver -y
REM winget install AMD.RyzenMaster -h

REM ***Instalar Navegadores e Programas para Internet***
REM winget install eloston.ungoogled-chromium -h
REM winget install Dropbox.Dropbox -h
REM winget install KDE.Falkon -h
REM winget install Mozilla.Firefox -h
REM winget install Opera.Opera -h
REM winget install PicoTorrent.PicoTorrent -h
REM winget install VivaldiTechnologies.Vivaldi -h
REM winget install Microsoft.OneDrive -h
REM winget install TIDALMusicAS.TIDAL -h

REM ***Instalar Aplicativos***
REM winget install calibre.calibre -h
REM winget install PeterPawlowski.foobar2000 -h
REM winget install IrfanSkiljan.IrfanView -h
REM cinst kis -y
REM winget install XBMCFoundation.Kodi -h
REM winget install CodeJelly.Launchy -h
REM cinst launchyqt -y
REM winget install LibreOffice.LibreOffice -h
REM winget install MacType.MacType -h
REM winget install Henry++.MemReduct -h
REM winget install MKVToolNix.MKVToolNix -h
REM winget install clsid2.mpc-hc -h
REM cinst mpc-be -y
REM cinst msiafterburner -y
REM winget install Notepad++.Notepad++ -h
REM winget install Microsoft.Office -h
REM cinst oldcalc -y
REM cinst openal -y
REM cinst paint.net -y
REM winget install QL-Win.QuickLook -h
REM winget install QuiteRSS.QuiteRSS -h
REM winget install PunkLabs.RocketDock -h
REM winget install Piriform.Speccy -h
REM winget install SumatraPDF.SumatraPDF -h
REM winget install RandomEngy.VidCoder -h
REM winget install VideoLAN.VLC -h
REM cinst windowblinds -y
REM winget install Microsoft.winfile -h
REM cinst xplorer2 -y
REM winget install ModernFlyouts.ModernFlyouts -h
REM winget install Files-Community.Files -h
REM winget install Open-Shell.Open-Shell-Menu -h
REM winget install t1m0thyj.WinDynamicDesktop -h

REM ***Instalar Utilitários***
REM winget install 7zip.7zip -h
REM winget install 7zip.7zipAlpha -h
REM winget install BleachBit.BleachBit -h
REM winget install Piriform.CCleaner -h
REM cinst compactgui -y
REM winget install CPUID.CPU-Z -h
REM winget install Piriform.Defraggler -h
REM cinst directx -y
REM cinst eset.nod32 -y
REM winget install flux.flux -h
REM winget install TechPowerUp.GPU-Z -h
REM winget install REALiX.HWiNFO -h
REM winget install Microsoft.PowerToys -h
REM winget install Rainmeter.Rainmeter -h
REM winget install Piriform.Recuva -h
REM cinst regscanner -y
REM winget install den4b.ReNamer -h
REM winget install AntibodySoftware.WizTree -h
REM winget install Microsoft.WindowsTerminal -h
REM winget install Lexikos.AutoHotkey -h

TIMEOUT /T 5
taskkill /f /im explorer.exe
start explorer.exe
msg %username% Otimizacao Finalizada com Sucesso
