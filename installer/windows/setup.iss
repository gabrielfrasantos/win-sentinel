#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{C9B1C34C-6AAA-4E01-B4F3-7B307B38CEED}
AppName=win-sentinel
AppVersion={#AppVersion}
AppPublisher=Gabriel Santos
AppPublisherURL=https://github.com/gabrielfrasantos/win-sentinel
AppSupportURL=https://github.com/gabrielfrasantos/win-sentinel/issues
AppUpdatesURL=https://github.com/gabrielfrasantos/win-sentinel/releases
DefaultDirName={autopf}\win-sentinel
DefaultGroupName=win-sentinel
AllowNoIcons=yes
OutputDir=..\..\installer-output
OutputBaseFilename=win-sentinel-{#AppVersion}-windows-setup
SetupIconFile=..\..\assets\icon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\win-sentinel.exe
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "startupicon"; Description: "Start win-sentinel with Windows (tray, scheduled runs, temperature watch)"; \
      GroupDescription: "Startup options:"
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
      GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[InstallDelete]
Type: filesandordirs; Name: "{app}\_internal"

[Files]
Source: "..\..\dist\win-sentinel\*"; DestDir: "{app}"; \
        Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\win-sentinel";                       Filename: "{app}\win-sentinel.exe"
Name: "{group}\{cm:UninstallProgram,win-sentinel}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\win-sentinel";                 Filename: "{app}\win-sentinel.exe"; \
      Tasks: desktopicon

[Run]
Filename: "{app}\win-sentinel.exe"; Parameters: "--enable-startup"; \
          Flags: runhidden waituntilterminated; Tasks: startupicon; Check: not Relaunching
Filename: "{app}\win-sentinel.exe"; \
          Description: "{cm:LaunchProgram,win-sentinel}"; \
          Flags: nowait postinstall skipifsilent
Filename: "{app}\win-sentinel.exe"; Flags: nowait; Check: Relaunching

[UninstallRun]
Filename: "{app}\win-sentinel.exe"; Parameters: "--disable-startup"; \
          Flags: runhidden waituntilterminated; RunOnceId: "RemoveStartupTask"

[Code]
function Relaunching(): Boolean;
begin
  Result := ExpandConstant('{param:RELAUNCH|0}') = '1';
end;

procedure QuitRunningApp();
var
  ResultCode: Integer;
begin
  if FileExists(ExpandConstant('{app}\win-sentinel.exe')) then
  begin
    Exec(ExpandConstant('{app}\win-sentinel.exe'), '--quit', '', SW_HIDE,
         ewWaitUntilTerminated, ResultCode);
    Sleep(2000);
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  QuitRunningApp();
  Result := '';
end;

function InitializeUninstall(): Boolean;
begin
  QuitRunningApp();
  Result := True;
end;
