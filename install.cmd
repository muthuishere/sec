@echo off
rem Install sec and its agent skill on Windows (cmd, no PowerShell needed). Re-run to upgrade.
rem   curl -fsSL -o install.cmd https://raw.githubusercontent.com/muthuishere/sec/main/install.cmd && install.cmd
setlocal
if "%SEC_BIN_DIR%"=="" (set "DEST=%USERPROFILE%\.local\bin") else (set "DEST=%SEC_BIN_DIR%")
if not exist "%DEST%" mkdir "%DEST%"
where go >nul 2>nul
if %errorlevel%==0 (
  set "GOBIN=%DEST%"
  go install github.com/muthuishere/sec/cmd/sec@latest || exit /b 1
) else (
  set "ARCH=amd64"
  if /i "%PROCESSOR_ARCHITECTURE%"=="ARM64" set "ARCH=arm64"
  curl.exe -fsSL "https://github.com/muthuishere/sec/releases/latest/download/sec_windows_%ARCH%.exe" -o "%DEST%\sec.exe" || exit /b 1
)
"%DEST%\sec.exe" skill install
echo sec installed in %DEST% - add it to PATH if it is not already
