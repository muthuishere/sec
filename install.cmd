@echo off
rem One line, Windows cmd (no PowerShell):
rem   curl.exe -fsSL https://raw.githubusercontent.com/muthuishere/sec/main/install.cmd -o "%TEMP%\sec-install.cmd" && "%TEMP%\sec-install.cmd"
rem Downloads sec, puts it on your user PATH, installs the agent skill into %USERPROFILE%\.claude\skills and .agents\skills.
rem Re-run to upgrade.
setlocal
if "%SEC_BIN_DIR%"=="" (set "DEST=%USERPROFILE%\.local\bin") else (set "DEST=%SEC_BIN_DIR%")
if not exist "%DEST%" mkdir "%DEST%"
where go >nul 2>nul
if %errorlevel%==0 if "%SEC_NO_GO%"=="" (
  set "GOBIN=%DEST%"
  go install github.com/muthuishere/sec/cmd/sec@latest || exit /b 1
  goto :path
)
set "ARCH=amd64"
if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"
curl.exe -fsSL "https://github.com/muthuishere/sec/releases/latest/download/sec_windows_%ARCH%.exe" -o "%DEST%\sec.exe" || exit /b 1

:path
set "UPATH="
for /f "tokens=2,*" %%A in ('reg query HKCU\Environment /v Path 2^>nul') do set "UPATH=%%B"
echo ;%UPATH%; | find /i ";%DEST%;" >nul
if errorlevel 1 (
  if defined UPATH (setx Path "%UPATH%;%DEST%" >nul) else (setx Path "%DEST%" >nul)
  echo added %DEST% to your PATH - open a new terminal
)
"%DEST%\sec.exe" skill install
"%DEST%\sec.exe" version
