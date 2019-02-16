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
sc stop ICEsoundService
sc stop ClickToRunSvc
sc stop SEMgrSvc
sc stop RtkAudioUniversalService
sc stop BDESVC
sc stop TabletInputService
sc stop SstpSvc
sc stop NvTelemetryContainer
sc stop HomeGroupListener
sc stop HomeGroupProvider
sc stop lfsvc
sc stop MapsBroke
sc stop NetTcpPortSharing
sc stop SharedAccess
sc stop WbioSrv
sc stop WMPNetworkSvc

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
sc config ICEsoundService start= disabled
sc config ClickToRunSvc start= demand
sc config SEMgrSvc start= disabled
sc config RtkAudioUniversalService start= disabled
sc config BDESVC start= disabled
sc config TabletInputService start= disabled
sc config SstpSvc start= disabled
sc config NvTelemetryContainer start= disabled
sc config HomeGroupListener start= disabled
sc config HomeGroupProvider start= disabled
sc config lfsvc start= disabled
sc config MapsBroke start= disabled
sc config NetTcpPortSharing start= disabled
sc config SharedAccess start= disabled
sc config WbioSrv start= disabled
sc config WMPNetworkSvc start= disabled

REM *** Tweaks de tarefas agendadas ***
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentLogOn" /Disable
schtasks /Change /TN "Microsoft\Office\OfficeTelemetryAgentFallBack" /Disable
schtasks /Change /TN "Microsoft\Office\Office 15 Subscription Heartbeat" /Disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable

REM schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
REM schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
REM schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
REM schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable *** Not sure if should be disabled, maybe related to S.M.A.R.T.
REM schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
REM schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
REM schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
REM schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
REM The stubborn task Microsoft\Windows\SettingSync\BackgroundUploadTask can be Disabled using a simple bit change. I use a REG file for that (attached to this post).
REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
REM schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable
REM schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable

@rem *** Remover Telemetria e Coleta de Dados ***
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f

@REM Configurações -> Privacidade -> Geral -> Permitir aplicativos usar meu ID de propaganda
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
REM - Smart Screen para aplicativos da Store
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f
REM - Let websites provide locally...
reg add "HKCU\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f

@REM Desabilitar Sensor de Wifi
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" /v value /t REG_DWORD /d 0 /f
reg add "HKLM\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" /v value /t REG_DWORD /d 0 /f

@REM Mudar updates para notificar o agendamento de reinicialização
reg add "HKLM\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings" /v UxOption /t REG_DWORD /d 1 /f
@REM Disable P2P Update downlods outside of local network
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f

@REM *** Desabilitar Cortana e Telemetria ***
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f

REM *** Esconder a caixa de Procura da barra de Tarefas. Você ainda pode pesquisar apertando Win + o que você quer pesquisar. ***
REM 0 = esconder completamente, 1 = mostrar apenas ícone, 2 = Mostrar caixa completa
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "SearchboxTaskbarMode" /t REG_DWORD /d 0 /f

REM *** Desabilitar Jump lists dos apps XAML no menu iniciar ***
REM reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f

REM *** Configurar Windows Explorer para iniciar no Este Computador, ao invés de Acesso Rápido ***
REM 1 = Este Computador, 2 = Acesso Rápido
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f

REM *** Desabilitar sugestões no Menu Iniciar ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f

REM *** Desabilitar hibernação ***
powercfg -h off 

REM *** Desabilitar memória virtual ***
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
wmic pagefileset where name="C:\\pagefile.sys" delete

REM *** Desabilitar Superfetch ***
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d 00000000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d 00000000 /f

REM *** Acelerar desligamento ***
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f

REM *** Habilitar todos os icones na tray***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explore" /v "EnableAutoTray" /t REG_DWORD /d 0 /f

REM *** Tweaks Variados ***
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d 1 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d 1000 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d 20 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d 2000 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d 1000 /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d 8 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d 00000001 /f

REM *** Melhorar qualidade papel de parede ***
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 00000064 /f

REM *** Tirar animações inuteís ***
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "VisualFXSetting" /t REG_DWORD /d 2 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "VisualFXSetting" /t REG_DWORD /d 3 /f
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d 9012038010000000 /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" REG_SZ /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "DisablePreviewDesktop" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM " /V "DisablePreviewDesktop" /T REG_DWORD /D 0 /F
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "IconsOnly" /T REG_DWORD /D 1 /F
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ListviewAlphaSelect" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "DragFullWindows" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ListviewShadow" /T REG_DWORD /D 1 /F
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /V "AlwaysHibernateThumbnails" /T REG_DWORD /D 0 /F

REM *** Desabilitar Game Bar e DVR ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /V "AppCaptureEnabled" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /V "GameDVR_Enabled" /T REG_DWORD /D 0 /F
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /V "AllowgameDVR" /T REG_DWORD /D 0 /F

REM *** Desabilitar Controle de Conta de Usuário ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "PromptOnSecureDesktop" /T REG_DWORD /D 0 /F
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableLUA" /T REG_DWORD /D 1 /F
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "ConsentPromptBehaviorAdmin" /T REG_DWORD /D 0 /F

REM *** Cores no iniciar e barra de tarefas ***
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "AutoColorization " /t REG_DWORD /d 0 /f

REM *** Prompt de Comando por padrão ***
REG Add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V DontUsePowerShellOnWinX /T REG_DWORD /D 1 /F

REM *** Nunca Desligar HD ***
rem bateria
powercfg /SETDCVALUEINDEX SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0
rem tomada
powercfg /SETACVALUEINDEX SCHEME_CURRENT 0012ee47-9041-4b5d-9b77-535fba8b1442 6738e2c4-e8a5-4a42-b16a-e040e769756e 0

REM *** Desligar Monitor após 10 minutos de inatividade ***
rem bateria
powercfg /SETDCVALUEINDEX SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 600
rem tomada
powercfg /SETACVALUEINDEX SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 600

REM *** Desabilitar Protetor de tela ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /V "ScreenSaveActive" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /V "ScreenSaveActive" /T REG_DWORD /D 0 /F

REM *** Desabilitar SmartScreen ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableSmartScreen" /T REG_DWORD /D 0 /F
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /V "ShellSmartScreenLevel" /F

@rem Apenas alguns tweaks
REM *** Mostrar arquivos ocultos no Explorer ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f
 
REM *** Mostrar arquivos super ocultos no Explorer ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSuperHidden" /t REG_DWORD /d 1 /f

REM *** Mostrar extensões de arquivos no Explorer ***
REM reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t  REG_DWORD /d 0 /f

REM *** Desabilitar Armazenamento Reservado ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t  REG_DWORD /d 0 /f

REM *** Desabilitar Otimização de Entrega ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Settings" /v "DownloadMode" /t REG_SZ /d 0 /f

REM *** Desabilitar UAC ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "PromptOnSecureDesktop" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ConsentPromptBehaviorAdmin" /t REG_DWORD /d 0 /f

REM *** Desabilitar Localização ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d Deny /f

REM *** Desabilitar Avisos de Arquivos baixados na Internet ***
REG ADD "HKCU\Environment" /V "SEE_MASK_NOZONECHECKS" /T REG_SZ /D 1 /F
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /V "SEE_MASK_NOZONECHECKS" /T REG_SZ /D 1 /F

REM *** Desbloquear automaticamente arquivos de internet ***
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d 1 /f

REM *** Desabilitar Cortana e Websearch ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f

REM *** Desabilitar Atualizações Automáticas de Drivers ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v "LetAppsRunInBackground" /t REG_DWORD /d 2 /f

REM *** Desabilitar Propagandas ***
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f

REM *** Desabilitar acessibilidade de teclado ***
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\StickyKeys" /v "Flags" /t REG_SZ /d 506 /f
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\Keyboard Response" /v "Flags" /t REG_SZ /d 122 /f
reg add "HKEY_CURRENT_USER\Control Panel\Accessibility\ToggleKeys" /v "Flags" /t REG_SZ /d 58 /f

REM *** Desabilitar Apps em Segundo Plano ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d 2 /f

REM *** Desabilitar download automatico de drivers ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 0 /f

REM *** Desabilitar Edge em Segundo Plano ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "SyncFavoritesBetweenIEAndMicrosoftEdge" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "PreventLiveTileDataCollection" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" /v "AllowPrelaunch" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "PreventTabPreloading" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\MicrosoftEdge\TabPreloader" /v "AllowTabPreloading" /t REG_DWORD /d 0 /f

REM *** Tweaks variados de privacidade ***
PowerShell -Command "Set-WindowsSearchSetting -EnableWebResultsSetting $false"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d 0 /f
reg add "SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Type" /t REG_SZ /d LooselyCoupled /f
reg add "SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d Deny /f
reg add "SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "InitialAppValue" /t REG_SZ /d Unspecified /f
reg add "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" /v "WiFiSenseCredShared" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\features" /v "WiFiSenseOpen" /t REG_DWORD /d 0 /f

REM *** Desabilitar Delay de Inicialização ***
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "Startupdelayinmsec" /t REG_DWORD /d 0 /f

REM *** Corrigir Erro de app padrão foi resetado ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppXvhc4p7vz4b485xfp46hhk3fq3grkdgjg" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppX4hxtad77fbk3jkkeerkrm0ze94wjf3s9" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppXde74bfzw9j31bzhcvsrxsyjnhhbq66cs" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppXde74bfzw9j31bzhcvsrxsyjnhhbq66cs" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppXcc58vyzkbjbs4ky0mxrmxf8278rk9b3t" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppXcc58vyzkbjbs4ky0mxrmxf8278rk9b3t" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppXk0g4vb8gvt7b93tg50ybcy892pge6jmt" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppX43hnxtbyyps62jhe9sqpdzxn1790zetc" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppX9rkaq77s0jzh1tyccadx9ghba15r6t3h" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppXqj98qxeaynz6dv4459ayz6bnqxbyaqcs" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" /v "NoOpenWith" /t REG_SZ /d "" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AppX6eg8h5sxqq90pv53845wmnbewywdqq5h" /v "NoStaticDefaultVerb" /t REG_SZ /d "" /f

REM *** Desinstalar OneDrive ***
REM start /wait "" "%SYSTEMROOT%\SYSWOW64\ONEDRIVESETUP.EXE" /UNINSTALL
REM rd C:\OneDriveTemp /Q /S >NUL 2>&1
REM rd "%USERPROFILE%\OneDrive" /Q /S >NUL 2>&1
REM rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S >NUL 2>&1
REM rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S >NUL 2>&1
REM reg add "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
REM reg add "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}\ShellFolder" /f /v Attributes /t REG_DWORD /d 0 >NUL 2>&1
REM echo OneDrive has been removed. Windows Explorer needs to be restarted.
REM pause
REM start /wait TASKKILL /F /IM explorer.exe
REM start explorer.exe.

REM *** Remover Features Não Usadas ***
DISM.exe /Online /Disable-Feature /featurename:SimpleTCP  /Remove
DISM.exe /Online /Disable-Feature /featurename:SNMP   /Remove
DISM.exe /Online /Disable-Feature /featurename:WMISnmpProvider /Remove
DISM.exe /Online /Disable-Feature /featurename:Windows-Identity-Foundation  /Remove
DISM.exe /Online /Disable-Feature /featurename:DirectoryServices-ADAM-Client /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-WebServerRole /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-WebServer /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-CommonHttpFeatures /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-HttpErrors /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-HttpRedirect /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-ApplicationDevelopment /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-NetFxExtensibility /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-NetFxExtensibility45 /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-HealthAndDiagnostics /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-HttpLogging /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-LoggingLibraries /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-RequestMonitor /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-HttpTracing  /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-Security /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-URLAuthorization /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-RequestFiltering /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-IPSecurity /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-Performance /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-HttpCompressionDynamic /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-WebServerManagementTools /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-ManagementScriptingTools /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-IIS6ManagementCompatibility /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-Metabase /Remove
DISM.exe /Online /Disable-Feature /featurename:WAS-WindowsActivationService /Remove
DISM.exe /Online /Disable-Feature /featurename:WAS-ProcessModel /Remove
DISM.exe /Online /Disable-Feature /featurename:WAS-NetFxEnvironment /Remove
DISM.exe /Online /Disable-Feature /featurename:WAS-ConfigurationAPI /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-HostableWebCore /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-CertProvider /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-WindowsAuthentication /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-DigestAuthentication /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-ClientCertificateMappingAuthentication /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-IISCertificateMappingAuthentication /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-ODBCLogging /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-StaticContent /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-DefaultDocument /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-DirectoryBrowsing /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-WebDAV /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-WebSockets /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-ApplicationInit /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-ASPNET /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-ASPNET45 /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-ASP /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-CGI /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-ISAPIExtensions /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-ISAPIFilter /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-ServerSideIncludes /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-CustomLogging /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-BasicAuthentication /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-HttpCompressionStatic /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-ManagementConsole /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-ManagementService /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-WMICompatibility /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-LegacyScripts /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-LegacySnapIn /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-FTPServer /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-FTPSvc /Remove
DISM.exe /Online /Disable-Feature /featurename:IIS-FTPExtensibility /Remove
DISM.exe /Online /Disable-Feature /featurename:MSMQ-Container /Remove
DISM.exe /Online /Disable-Feature /featurename:MSMQ-Server /Remove
DISM.exe /Online /Disable-Feature /featurename:MSMQ-Triggers /Remove
DISM.exe /Online /Disable-Feature /featurename:MSMQ-ADIntegration /Remove
DISM.exe /Online /Disable-Feature /featurename:MSMQ-HTTP /Remove
DISM.exe /Online /Disable-Feature /featurename:MSMQ-Multicast /Remove
DISM.exe /Online /Disable-Feature /featurename:MSMQ-DCOMProxy /Remove
DISM.exe /Online /Disable-Feature /featurename:WCF-HTTP-Activation45 /Remove
DISM.exe /Online /Disable-Feature /featurename:WCF-TCP-Activation45 /Remove
DISM.exe /Online /Disable-Feature /featurename:WCF-Pipe-Activation45 /Remove
DISM.exe /Online /Disable-Feature /featurename:WCF-MSMQ-Activation45 /Remove
DISM.exe /Online /Disable-Feature /featurename:WCF-HTTP-Activation /Remove
DISM.exe /Online /Disable-Feature /featurename:WCF-NonHTTP-Activation /Remove
DISM.exe /Online /Disable-Feature /featurename:NetFx4Extended-ASPNET45 /Remove
DISM.exe /Online /Disable-Feature /featurename:MediaPlayback /Remove
DISM.exe /Online /Disable-Feature /featurename:WindowsMediaPlayer /Remove
DISM.exe /Online /Disable-Feature /featurename:Microsoft-Windows-MobilePC-Client-Premium-Package-net /Remove
DISM.exe /Online /Disable-Feature /featurename:Printing-XPSServices-Features /Remove
DISM.exe /Online /Disable-Feature /featurename:RasCMAK /Remove
DISM.exe /Online /Disable-Feature /featurename:RasRip /Remove
DISM.exe /Online /Disable-Feature /featurename:MSRDC-Infrastructure /Remove
DISM.exe /Online /Disable-Feature /featurename:TelnetClient /Remove
DISM.exe /Online /Disable-Feature /featurename:TelnetServer /Remove
DISM.exe /Online /Disable-Feature /featurename:TFTP /Remove
DISM.exe /Online /Disable-Feature /featurename:TIFFIFilter /Remove
DISM.exe /Online /Disable-Feature /featurename:WorkFolders-Client /Remove
DISM.exe /Online /Disable-Feature /featurename:SMB1Protocol /Remove
DISM.exe /Online /Disable-Feature /featurename:Microsoft-Hyper-V-All  /Remove
DISM.exe /Online /Disable-Feature /featurename:Microsoft-Hyper-V-Tools-All   /Remove
DISM.exe /Online /Disable-Feature /featurename:Microsoft-Hyper-V /Remove
DISM.exe /Online /Disable-Feature /featurename:Microsoft-Hyper-V-Management-Clients /Remove
DISM.exe /Online /Disable-Feature /featurename:Microsoft-Hyper-V-Management-PowerShell /Remove

REM Remover Apps da Store
PowerShell -Command "Get-AppxPackage *3DBuilder* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Cortana* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Getstarted* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsAlarms* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsCamera* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *bing* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MicrosoftOfficeHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *OneNote* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *people* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *photos* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *SkypeApp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *solit* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsSoundRecorder* | Remove-AppxPackage"
REM PowerShell -Command "Get-AppxPackage *xbox* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *windowscommunicationsapps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *zune* | Remove-AppxPackage"
REM PowerShell -Command "Get-AppxPackage *WindowsCalculator* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsMaps* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Sway* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *CommsPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *ConnectivityStore* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Microsoft.Messaging* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *ContentDeliveryManager* | Remove-AppxPackage"
REM PowerShell -Command "Get-AppxPackage *Microsoft.WindowsStore* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *BubbleWitch3Saga* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *CandyCrushSodaSaga* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsFeedbackHub* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *GetHelp* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MarchofEmpires* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Wallet* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MixedReality.Portal* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *OneConnect* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *DisneyMagicKingdoms* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MsPaint* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Print3D* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *TuneInRadio* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Twitter* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Appconnector* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Advertising.Xaml* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MicrosoftSolitaireCollection* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MicrosoftPowerBIForWindows* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *MinecraftUWP* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *NetworkSpeedTest* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *ZuneMusic* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *ZuneVideo* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Messaging* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *OneConnect* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WindowsReadingList* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *YourPhone* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Flipboard* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Shazam* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *CandyCrushSaga* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *iHeartRadio* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Netflix* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Wunderlist* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *DrawboardPDF* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *PhotoStudio* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *FarmVille2CountryEscape* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Asphalt8Airborne* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Facebook* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *RoyalRevolt2* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *CaesarsSlotsFreeCasino* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Keeper* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *PhototasticCollage* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *XING* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *AutodeskSketchBook* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Duolingo-LearnLanguagesforFree* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *EclipseManager* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *562882FEEB491* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *DolbyAccess* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *SpotifyMusic* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *WinZipUniversal* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *Plex* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *LinkedInforWindows* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *PolarrPhotoEditorAcademicEdition* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *FitbitCoach* | Remove-AppxPackage"
PowerShell -Command "Get-AppxPackage *COOKINGFEVER* | Remove-AppxPackage"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d 2 /f
reg add "SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f

REM ***Instalar MVPS HOSTS (Desabilita propagandas e rastreadores)
Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/robledosm/update-mvpsHosts/master/update-mvpsHosts.ps1'))"
Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/W4RH4WK/Debloat-Windows-10/master/scripts/block-telemetry.ps1'))"

REM ***Instalar Chocolatey***
Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
call %programdata%\chocolatey\bin\RefreshEnv.cmd

REM ***Instalar Clientes Jogos***
choco install goggalaxy -y
choco install steam -y
choco install origin -y
choco install uplay -y
choco install epicgameslauncher -y

REM ***Instalar Emuladores***
REM choco install retroarch -y
REM choco install dolphin -y
REM choco install cemu -y
REM choco install nestopia -y
REM choco install snes9x -y
REM choco install fs-uae -y
REM choco install mame -y
REM choco install winvice -y
REM choco install visualboyadvance -y
REM choco install ppsspp -y

REM ***Instalar Outros Aplicativos***
REM choco install dropbox -y
REM choco install nvidia-display-driver -y
REM choco install realtek-hd-audio-driver -y
REM choco install office365proplus -y
REM choco install 7zip.install -y
REM choco install bleachbit -y
REM choco install calibre -y
REM choco install ccleaner -y
REM choco install falkon -y
REM choco install foobar2000 -y
REM choco install kodi -y
REM choco install launchy-beta -y
REM choco install chromium -y
REM choco install compactgui -y
REM choco install defraggler -y
REM choco install discord -y
REM choco install firefox -y
REM choco install f.lux -y
REM choco install hwinfo -y
REM choco install irfanview -y
REM choco install libreoffice-fresh -y
REM choco install mpc-hc -y
REM choco install eset.nod32 -y
REM choco install kis -y
REM choco install notepadplusplus -y
REM choco install openal -y
REM choco install directx -y
REM choco install opera -y
REM choco install paint.net -y
REM choco install playnite -y
REM choco install quicklook -y
REM choco install rainmeter -y
REM choco install recuva -y
REM choco install renamer -y
REM choco install rocketdock -y
REM choco install speccy -y
REM choco install sumatrapdf -y
REM choco install vivaldi -y
REM choco install wiztree -y
REM choco install xplorer2 -y
REM choco install multicommander -y
REM choco install winfile -y
REM choco install regscanner -y
choco install oldcalc -y
