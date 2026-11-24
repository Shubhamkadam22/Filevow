; Inno Setup 6 script for the FileVow installer (build.ps1 runs it).
; Installs for the current Windows user only, so no administrator rights are needed.

#define AppName "FileVow"
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{6C3E3C2B-6C1F-4C0B-9F0E-2B7A6D5F1A10}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher=FileVow
VersionInfoVersion={#AppVersion}
DefaultDirName={localappdata}\Programs\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.19044
OutputDir=..\dist
OutputBaseFilename=FileVow-Setup-{#AppVersion}
SetupIconFile=build\filevow.ico
UninstallDisplayIcon={app}\FileVow.exe
WizardStyle=modern
Compression=lzma2/max
SolidCompression=yes
CloseApplications=yes

[Tasks]
Name: "autostart"; Description: "Keep monitoring in the background when I sign in to Windows (recommended)"; GroupDescription: "Monitoring:"
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "build\dist\FileVow\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{userprograms}\{#AppName}"; Filename: "{app}\FileVow.exe"; Comment: "Open FileVow"
Name: "{userdesktop}\{#AppName}"; Filename: "{app}\FileVow.exe"; Tasks: desktopicon

[Registry]
; Same entry `FileVow.exe autostart on` writes; removed again on uninstall.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#AppName}"; \
  ValueData: """{app}\FileVow.exe"" desktop --background"; Tasks: autostart; Flags: uninsdeletevalue

[Run]
Filename: "{app}\FileVow.exe"; Description: "Open FileVow now"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Stop a running background copy so its files can be removed.
Filename: "{cmd}"; Parameters: "/C taskkill /IM FileVow.exe /F"; Flags: runhidden; RunOnceId: "StopFileVow"

[Messages]
FinishedLabel=FileVow is installed. Open it, create your account and choose the folders you want to protect. Your records stay in AppData\Local\FileVow, also after uninstalling.
