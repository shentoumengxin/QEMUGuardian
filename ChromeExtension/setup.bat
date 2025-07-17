@echo off
setlocal enableDelayedExpansion

echo =========================================================
echo Qemu Guardian Native Host Installation Script (Windows)
echo =========================================================
echo.

:: --- 1. Get Chrome Extension ID ---
set "CHROME_EXTENSION_ID="
set /p "CHROME_EXTENSION_ID=Please enter your Chrome Extension ID (e.g., abcdefghijklmnopqrstuvwxyzabcdef): "
if not defined CHROME_EXTENSION_ID (
    echo Error: Chrome Extension ID cannot be empty. Exiting.
    goto :eof
)

:: --- Validate Chrome Extension ID format ---
set "VALID=true"
if "!CHROME_EXTENSION_ID:~32!"=="" (
    :: Check if length is exactly 32.
    for /l %%i in (0,1,31) do (
        set "temp_char=!CHROME_EXTENSION_ID:~%%i,1!"
        if "!temp_char!"=="" set "VALID=false"
    )
    if not "!CHROME_EXTENSION_ID:~32,1!"=="" set "VALID=false"
) else (
    set "VALID=false"
)

:: Check if all characters are 'a' through 'p' (simplistic, but effective for batch)
for /l %%i in (0,1,31) do (
    set "CHAR=!CHROME_EXTENSION_ID:~%%i,1!"
    if "!CHAR!" geq "q" (
        set "VALID=false"
    )
)

if "!VALID!"=="false" (
    echo Error: Invalid Chrome Extension ID format.
    echo ID must be exactly 32 characters long and contain only lowercase letters 'a' through 'p'.
    goto :eof
)

:: --- 2. Define Paths ---
set "ROOT_DIR=%~dp0"
set "BIN_DIR=%ROOT_DIR%bin\windows\"
set "EXECUTABLE_NAME=Guardian.exe"
set "EXECUTABLE_SOURCE_PATH=%BIN_DIR%%EXECUTABLE_NAME%"
set "MANIFEST_TEMPLATE_PATH=%ROOT_DIR%guardian_manifest.json.template"
set "NATIVE_HOST_NAME=com.nus_dada_group.guardian"

:: --- 3. Validate Source Files ---
if not exist "%EXECUTABLE_SOURCE_PATH%" (
    echo Error: %EXECUTABLE_NAME% not found at "%EXECUTABLE_SOURCE_PATH%". Please build it first.
    goto :eof
)
if not exist "%MANIFEST_TEMPLATE_PATH%" (
    echo Error: guardian_manifest.json.template not found at "%MANIFEST_TEMPLATE_PATH%".
    goto :eof
)

:: --- 4. Get User Defined Install Location for Backend Service ---
echo.
echo --- Backend Service Installation Path ---
echo The Guardian.exe, its DLLs, AND the Native Host manifest will be copied to this location.
echo Default path: %ROOT_DIR%bin\windows\ (current compiled location)
set "INSTALL_PATH_DEFAULT=%ROOT_DIR%bin\windows"
set "INSTALL_PATH="
set /p "INSTALL_PATH=Enter desired installation path for Guardian.exe (or press Enter for default): "
if not defined INSTALL_PATH (
    set "INSTALL_PATH=%INSTALL_PATH_DEFAULT%"
) else (
    :: Normalize path by removing trailing backslash if present
    if "%INSTALL_PATH:~-1%"=="\" set "INSTALL_PATH=%INSTALL_PATH:~0,-1%"
)

echo Selected installation path: !INSTALL_PATH!
echo.

:: --- 5. Create Installation Directory and Copy Files ---
echo Creating installation directory...
mkdir "!INSTALL_PATH!" 2>nul
if not exist "!INSTALL_PATH!" (
    echo Error: Failed to create directory "!INSTALL_PATH!". Please check permissions or path validity.
    goto :eof
)

echo Copying %EXECUTABLE_NAME% and required DLLs to "!INSTALL_PATH!"...
xcopy "%BIN_DIR%*.dll" "!INSTALL_PATH!\" /Y /E /Q
copy "%EXECUTABLE_SOURCE_PATH%" "!INSTALL_PATH!\" /Y >nul
if %errorlevel% neq 0 (
    echo Error: Failed to copy files to "!INSTALL_PATH!".
    goto :eof
)
set "ACTUAL_EXECUTABLE_PATH=!INSTALL_PATH!\!EXECUTABLE_NAME!"

:: --- NEW: 6. Generate and Place Native Host Manifest in the installation directory ---
echo Generating Native Host manifest in "!INSTALL_PATH!"...

set "FINAL_MANIFEST_PATH=!INSTALL_PATH!\%NATIVE_HOST_NAME%.json"
:: Escape backslashes for JSON path (for the 'path' field inside the JSON)
set "ESCAPED_EXECUTABLE_PATH=!ACTUAL_EXECUTABLE_PATH:\=\\%!"

:: Write manifest directly to the final location
(
    for /f "usebackq delims=" %%A in ("%MANIFEST_TEMPLATE_PATH%") do (
        set "LINE=%%A"
        setlocal enabledelayedexpansion
        set "LINE=!LINE:YOUR_EXTENSION_ID_PLACEHOLDER=%CHROME_EXTENSION_ID%!"
        set "LINE=!LINE:YOUR_GUARDIAN_EXECUTABLE_PATH_PLACEHOLDER=%EXECUTABLE_NAME%!"
        echo !LINE!
        endlocal
    )
) > "!FINAL_MANIFEST_PATH!"

if not exist "!FINAL_MANIFEST_PATH!" (
    echo Error: Failed to create manifest file at "!FINAL_MANIFEST_PATH!".
    goto :eof
)

:: --- 7. Register Native Host via Registry ---
echo Registering Native Host in Windows Registry...

:: Escape backslashes for the REG file path
set "MANIFEST_PATH_FOR_REG=!FINAL_MANIFEST_PATH:\=\\%!"
set "TEMP_REG_FILE=%TEMP%\%NATIVE_HOST_NAME%.reg"

(
    echo Windows Registry Editor Version 5.00
    echo.
    echo [HKEY_CURRENT_USER\SOFTWARE\Google\Chrome\NativeMessagingHosts\%NATIVE_HOST_NAME%]
    echo @="%MANIFEST_PATH_FOR_REG%"
) > "%TEMP_REG_FILE%"

reg import "%TEMP_REG_FILE%"
if %errorlevel% neq 0 (
    echo Error: Failed to import registry file. You might need to run this script as Administrator.
    del "!FINAL_MANIFEST_PATH!" "%TEMP_REG_FILE%"
    goto :eof
)

:: --- 8. Cleanup Temporary Registry File ---
del "%TEMP_REG_FILE%"

echo.
echo =========================================================
echo Installation Complete!
echo The Native Host "%NATIVE_HOST_NAME%" has been registered.
echo Guardian.exe, its DLLs, and manifest are located at: "!INSTALL_PATH!"
echo You can now load/reload the Chrome Extension.
echo =========================================================
echo.

pause
endlocal