chcp 65001
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
sc stop RstMwService
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
sc config RstMwService start= disabled
sc config DusmSvc start= disabled
sc config BthAvctpSvc start= disabled
sc config BITS start= demand
sc config DPS start= disabled


REM *** Tweaks de tarefas agendadas ***
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /Disable
schtasks /Change /TN "Microsoft\Windows\SystemRestore\SR" /Disable
schtasks /Change /TN "Microsoft\Office\Office Automatic Updates 2.0" /Disable
schtasks /Change /TN "Microsoft\Office\Office ClickToRun Service Monitor" /Disable
schtasks /Change /TN "Microsoft\Office\Office Feature Updates" /Disable
schtasks /Change /TN "Microsoft\Office\Office Feature Updates Logon" /Disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /Disable
schtasks /Change /TN "MicrosoftEdgeUpdateTaskMachineCore" /Disable
schtasks /Change /TN "MicrosoftEdgeUpdateTaskMachineUA" /Disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /Disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /Disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /Disable
REM schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
REM schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /Disable *** Not sure if should be disabled, maybe related to S.M.A.R.T.
REM schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable
REM schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable
REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\ForceSynchronizeTime" /Disable
REM schtasks /Change /TN "Microsoft\Windows\Time Synchronization\SynchronizeTime" /Disable
REM schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable

@rem *** Remover Telemetria e Coleta de Dados ***
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Metadata" /v PreventDeviceMetadataFromNetwork /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f
REG ADD HKLM\Software\Microsoft\SQMClient\Windows /v CEIPEnable /d 0 /t REG_DWORD /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\SQMLogger" /v "Start" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d Off /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AppHost" /v "SmartScreenEnabled" /t "REG_SZ" /d "Off" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowFullControl /t REG_DWORD /d 0 /f


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
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v SystemSettingsDownloadMode /t REG_DWORD /d 0 /f

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
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d 2000 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d 5 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d 3000 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "LowLevelHooksTimeout" /t REG_SZ /d 2000 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "ActiveWndTrackTimeout" /t REG_DWORD /d 0000000a /f
reg add "HKEY_CURRENT_USER\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoLowDiskSpaceChecks" /t REG_DWORD /d 00000001 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "LinkResolveIgnoreLinkInfo" /t REG_DWORD /d 00000001 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveSearch" /t REG_DWORD /d 00000001 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoResolveTrack" /t REG_DWORD /d 00000001 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoInternetOpenWith" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DesktopLivePreviewHoverTime" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowRun" /t REG_DWORD /d 00000001 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet002\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d 2000 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnails" /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "FolderContentsInfoTip" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowEncryptCompressedColor" /t REG_DWORD /d 0 /f
REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V ShowInfoTip /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowPreviewHandlers" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f

REM *** Melhorar qualidade papel de parede ***
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 00000100 /f

REM *** Tirar animações inuteís ***
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "VisualFXSetting" /t REG_DWORD /d 3 /f
reg add "HKCU\Control Panel\Desktop" /v "UserPreferencesMask" /t REG_BINARY /d 9032078010000000 /f
reg add "HKCU\Control Panel\Desktop\WindowMetrics" /v "MinAnimate" REG_SZ /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAnimations" /t REG_DWORD /d 0 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "DisablePreviewDesktop" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM " /V "DisablePreviewDesktop" /T REG_DWORD /D 0 /F
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "IconsOnly" /T REG_DWORD /D 1 /F
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ListviewAlphaSelect" /T REG_DWORD /D 1 /F
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "DragFullWindows" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "FontSmoothing" /t REG_SZ /d 2 /f
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V "ListviewShadow" /T REG_DWORD /D 1 /F
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\DWM" /V "AlwaysHibernateThumbnails" /T REG_DWORD /D 0 /F

REM *** Desabilitar Game Bar e DVR ***
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /V "AppCaptureEnabled" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\GameDVR" /V "GameDVR_Enabled" /T REG_DWORD /D 0 /F
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /V "AllowgameDVR" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /V "AllowAutoGameMode" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Software\Microsoft\GameBar" /V "AutoGameModeEnabled" /T REG_DWORD /D 0 /F

REM *** Desabilitar Controle de Conta de Usuário *** Impacta em programas UWP, como XBOX
rem reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "PromptOnSecureDesktop" /T REG_DWORD /D 0 /F
rem reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "EnableLUA" /T REG_DWORD /D 1 /F
rem reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /V "ConsentPromptBehaviorAdmin" /T REG_DWORD /D 0 /F

REM *** Cores no iniciar e barra de tarefas ***
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /t REG_DWORD /d 1 /f
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "AutoColorization " /t REG_DWORD /d 0 /f

REM *** Prompt de Comando por padrão ***
REG Add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /V DontUsePowerShellOnWinX /T REG_DWORD /D 1 /F

REM *** Desabilitar Protetor de tela ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" /V "ScreenSaveActive" /T REG_DWORD /D 0 /F
reg add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Control Panel\Desktop" /V "ScreenSaveActive" /T REG_DWORD /D 0 /F

REM *** Desabilitar SmartScreen ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /V "EnableSmartScreen" /T REG_DWORD /D 0 /F
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /V "ShellSmartScreenLevel" /F

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
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexingOutlook" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "PreventIndexingEmailAttachments" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AutoIndexSharedFolders" /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f

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

REM *** Desabilitar inicialização rápida ***
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /V HiberbootEnabled /T REG_dWORD /D 0 /F

REM *** Desabilitar Notificações Balão ***
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /V EnableBalloonTips /T REG_dWORD /D 0 /F

REM *** Tweaks de Rede ***
netsh interface teredo set state disable
netsh interface 6to4 set state disable disable
netsh interface isatap set state disable
REG ADD "HKLM\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters" /v "EnableICSIPv6" /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\services\TCPIP6\Parameters" /v "DisabledComponents" /t REG_DWORD /d 255 /f

REM *** Mostrar todos os icones na area de notificação ***
REG ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer" /V EnableAutoTray /T REG_DWORD /D 0 /F

REM *** Desabilitar questões de segurança para contas locais ***
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\System" /V NoLocalPasswordResetQuestion /T REG_DWORD /D 1 /F

REM *** Melhorar Scaling ***
REG ADD "HKEY_CURRENT_USER\Control Panel\Desktop" /V EnablePerProcessSystemDPI /T REG_DWORD /D 1 /F

REM *** Habilitar Modo Escuro ***
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /V AppsUseLightTheme /T REG_DWORD /D 0 /F

REM *** Desabilitar Hotspot 2.0 ***
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\WlanSvc\AnqpCache" /V OsuRegistrationStatus /T REG_DWORD /D 1 /F
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\icssvc" /V Start /T REG_DWORD /D 4 /F

REM *** Desabilitar Touchscreen ***
REG ADD "HKEY_CURRENT_USER\Software\Microsoft\Wisp\Touch" /V TouchGate /T REG_DWORD /D 0 /F

REM *** Desabilitar Transparencias e efeitos de cores ***
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 0 /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /t REG_DWORD /d 0 /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v ColorPrevalence /t REG_DWORD /d 0 /f
Reg Add "HKEY_CURRENT_USER\Control Panel\Desktop" /v AutoColorization /t REG_DWORD /d 0 /f

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

REM *** Instalar .NET Framework 3.5 ***
Dism /online /norestart /Enable-Feature /FeatureName:"NetFx3"

REM *** Dark Mode Janelas Win32 ***
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v ColorPrevalence /t REG_DWORD /d 1 /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v AccentColor /t REG_DWORD /d 171717 /f
Reg Add "HKCU\SOFTWARE\Microsoft\Windows\DWM" /v AccentColorInactive /t REG_DWORD /d 444444 /f

REM *** Desabilitar iniciar apps após reiniciar ***
Reg Add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v RestartApps /t REG_DWORD /d 0 /f

REM *** Tiles transparentes no Iniciar ***
Reg Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\0\2093230218" /v EnabledState /t REG_DWORD /d 2 /f
Reg Add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\0\2093230218" /v EnabledStateOptions /t REG_DWORD /d 0 /f

REM *** Inserir 5 abas mais recentes do Edge no Alt-Tab ***
Reg Add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v EnabledState /t REG_DWORD /d 1 /f

REM *** Remover Features Não Usadas ***
DISM.exe /Online /norestart /Disable-Feature /featurename:SimpleTCP /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:SNMP /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:WMISnmpProvider /Remove
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
DISM.exe /Online /norestart /Disable-Feature /featurename:Microsoft-Windows-MobilePC-Client-Premium-Package-net /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:Printing-XPSServices-Features /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:RasCMAK /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:RasRip /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:MSRDC-Infrastructure /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:TelnetClient /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:TelnetServer /Remove
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
DISM.exe /Online /norestart /Disable-Feature /featurename:Internet-Explorer-Optional-amd64 /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:Printing-Foundation-Features /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:FaxServicesClientPackage /Remove
DISM.exe /Online /norestart /Disable-Feature /featurename:Printing-Foundation-InternetPrinting-Client /Remove

REM Remover Apps da Store
Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "Get-AppxPackage | where-object {$_.name -notlike '*store*'} | where-object {$_.name -notlike '*xbox*'} | Remove-AppxPackage"
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314563Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\WindowsStore" /v "AutoDownload" /t REG_DWORD /d 2 /f
reg add "SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f

REM ***Instalar MVPS HOSTS (Desabilita propagandas e rastreadores)***
REM Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/robledosm/update-mvpsHosts/master/update-mvpsHosts.ps1'))"
REM Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://raw.githubusercontent.com/W4RH4WK/Debloat-Windows-10/master/scripts/block-telemetry.ps1'))"
REM ipconfig /flushdns
reg add "HKLM\SYSTEM\CurrentControlSet\services\Dnscache\Parameters" /v "MaxNegativeCacheTtl" /t "REG_DWORD" /d "0" /f
reg add "HKLM\SYSTEM\CurrentControlSet\services\Dnscache\Parameters" /v "MaxCacheTtl" /t "REG_DWORD" /d "1" /f

REM ***Instalar Chocolatey***
REM Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
REM call %programdata%\chocolatey\bin\RefreshEnv.cmd

REM ***Instalar Winget***
Powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "Add-AppxPackage -Path https://github.com/microsoft/winget-cli/releases/download/v1.2.3411-preview/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"

REM *** Desabilitar reserva de armazenamento ***
Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v ShippedWithReserves /t REG_DWORD /d 0 /f
Reg Add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v PassedPolicy /t REG_DWORD /d 0 /f

REM *** Desabilitar centro de notificações ***
REM REG ADD "HKCU\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableNotificationCenter /t REG_DWORD /d 1 /f

REM *** Desabilitar aplicativos em segundo plano ***
Reg Add HKCU\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications /v GlobalUserDisabled /t REG_DWORD /d 1 /f
Reg Add HKCU\Software\Microsoft\Windows\CurrentVersion\Search /v BackgroundAppGlobalToggle /t REG_DWORD /d 0 /f

REM *** Desabilitar Esconder itens na bandeja do sistema ***
REG ADD HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer /v NoAutoTrayNotify /d 1 /t REG_DWORD /f

REM *** Background em Cor Sólida ***
REG ADD "HKEY_CURRENT_USER\Control Panel\Colors" /v Background /t REG_SZ /d "1 133 116" /f

REM *** Desabilitar pastas especiais, como Música ***
REG ADD "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\Bags\AllFolders\Shell" /V FolderType /T REG_SZ /D NotSpecified /F

REM *** Desabilitar Windows Defender***
REM REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /d 1 /t REG_DWORD /f
REM REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /f
REM REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableBehaviorMonitoring /d 1 /t REG_DWORD /f
REM REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnAccessProtection /d 1 /t REG_DWORD /f
REM REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v DisableOnDisableScanOnRealtimeEnableAccessProtection /d 1 /t REG_DWORD /f

REM *** Desabilitar barra de pessoas ***
REG ADD "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /v HidePeopleBar /d 1 /t REG_DWORD /f

REM *** Desabilitar Assistência Remota ***
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /d 0 /t REG_DWORD /f

REM *** Habiltar agendamento de aceleração de GPU ***
REG ADD "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v HwSchMode /d 2 /t REG_DWORD /f

REM *** Desabilitar Histórico do Acesso Rápido ***
REG delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}" /f
REG delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}" /f
REG delete "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f
REG delete "HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}" /f

REM *** Habilitar Printscreen para abrir Snipping Tool ***

REG ADD "HKEY_CURRENT_USER\Control Panel\Keyboard" /v PrintScreenKeyForSnippingEnabled /d 1 /t REG_DWORD /f

REM *** Alterar Tamanho de Cache de Icones ***
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "Max Cached Icons" /t REG_SZ /d 4096 /f

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
icacls "%%LocalAppData%\Spotify\Storage" /deny *S-1-1-0:(F)

REM ***Instalar Clientes de Jogos ***

REM winget install EpicGames.EpicGamesLauncher -h
REM winget install GOG.Galaxy -h
REM winget install ElectronicArts.EADesktop -h
REM winget install Valve.Steam -h
REM winget install Ubisoft.Connect -h
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
REM cinst memreduct -y
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
REM cinst rainmeter -y
REM winget install Piriform.Recuva -h
REM cinst regscanner -y
REM cinst renamer -y
REM winget install AntibodySoftware.WizTree -h
REM winget install Microsoft.WindowsTerminal -h
REM winget install Lexikos.AutoHotkey -h

TIMEOUT /T 5
taskkill /f /im explorer.exe
start explorer.exe
msg %username% Otimizacao Finalizada com Sucesso
