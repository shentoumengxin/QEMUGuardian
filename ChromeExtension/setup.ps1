<#
.SYNOPSIS
Qemu Guardian Native Host Installation Script (Windows)

.DESCRIPTION
This script installs the Guardian backend service and registers it as a Chrome Native Messaging Host.
#>

# --- 1. Get Chrome Extension ID ---
Write-Host "========================================================="
Write-Host "Qemu Guardian Native Host Installation Script (Windows)"
Write-Host "========================================================="
Write-Host ""

$chromeExtensionId = Read-Host "Please enter your Chrome Extension ID (e.g., abcdefghijklmnopqrstuvwxyzabcdef)"
if ([string]::IsNullOrEmpty($chromeExtensionId)) {
    Write-Host "Error: Chrome Extension ID cannot be empty. Exiting."
    exit
}

# --- Validate Chrome Extension ID format ---
if ($chromeExtensionId.Length -ne 32 -or $chromeExtensionId -notmatch '^[a-p]+$') {
    Write-Host "Error: Invalid Chrome Extension ID format."
    Write-Host "ID must be exactly 32 characters long and contain only lowercase letters 'a' through 'p'."
    exit
}

# --- 2. Define Paths ---
$rootDir = $PSScriptRoot + "\"
$binDir = Join-Path $rootDir "bin\windows\"
$executableName = "Guardian.exe"
$executableSourcePath = Join-Path $binDir $executableName
$manifestTemplatePath = Join-Path $rootDir "guardian_manifest.json.template"
$nativeHostName = "com.nus_dada_group.guardian"

# --- 3. Validate Source Files ---
if (-not (Test-Path $executableSourcePath)) {
    Write-Host "Error: $executableName not found at '$executableSourcePath'. Please build it first."
    exit
}

if (-not (Test-Path $manifestTemplatePath)) {
    Write-Host "Error: guardian_manifest.json.template not found at '$manifestTemplatePath'."
    exit
}

# --- 4. Get User Defined Install Location for Backend Service ---
Write-Host ""
Write-Host "--- Backend Service Installation Path ---"
Write-Host "The Guardian.exe, its DLLs, AND the Native Host manifest will be copied to this location."
Write-Host "Default path: $binDir (current compiled location)"

$installPathDefault = $binDir
$installPath = Read-Host "Enter installation path for Guardian.exe (or press Enter for default)"
if ([string]::IsNullOrEmpty($installPath)) {
    $installPath = $installPathDefault
} else {
    # Normalize path by removing trailing backslash if present
    $installPath = $installPath.TrimEnd('\')
}

Write-Host "Selected installation path: $installPath"
Write-Host ""

# --- 5. Create Installation Directory and Copy Files ---
Write-Host "Creating installation directory..."
try {
    if (-not (Test-Path $installPath)) {
        New-Item -ItemType Directory -Path $installPath -Force | Out-Null
    }
} catch {
    Write-Host "Error: Failed to create directory '$installPath'. Please check permissions or path validity."
    exit
}

# 只有当目标路径与源路径不同时才执行复制
if ($installPath -ne $binDir) {
    Write-Host "Copying $executableName and required DLLs to '$installPath'..."
    try {
        # 复制所有 DLL 文件
        Get-ChildItem -Path "$binDir\*.dll" | ForEach-Object {
            $destination = Join-Path $installPath $_.Name
            if ($_.FullName -ne $destination) {
                Copy-Item -Path $_.FullName -Destination $destination -Force
            }
        }
        
        # 复制可执行文件
        $destinationExe = Join-Path $installPath $executableName
        if ($executableSourcePath -ne $destinationExe) {
            Copy-Item -Path $executableSourcePath -Destination $destinationExe -Force
        }
    } catch {
        Write-Host "Error: Failed to copy files to '$installPath'."
        Write-Host "Error details: $_"
        exit
    }
} else {
    Write-Host "Skipping file copy as installation path is same as source path."
}

$actualExecutablePath = Join-Path $installPath $executableName
# --- 6. Generate and Place Native Host Manifest in the installation directory ---
Write-Host "Generating Native Host manifest in '$installPath'..."

$finalManifestPath = Join-Path $installPath "$nativeHostName.json"

try {
    $manifestContent = Get-Content $manifestTemplatePath -Raw
    $manifestContent = $manifestContent.Replace('YOUR_EXTENSION_ID_PLACEHOLDER', $chromeExtensionId)
    $manifestContent = $manifestContent.Replace('YOUR_GUARDIAN_EXECUTABLE_PATH_PLACEHOLDER', $actualExecutablePath.Replace('\', '\\'))
    
    Set-Content -Path $finalManifestPath -Value $manifestContent -Force
} catch {
    Write-Host "Error: Failed to create manifest file at '$finalManifestPath'."
    exit
}

# --- 7. Register Native Host via Registry ---
Write-Host "Registering Native Host in Windows Registry..."

$registryPath = "HKCU:\SOFTWARE\Google\Chrome\NativeMessagingHosts\$nativeHostName"
try {
    if (-not (Test-Path $registryPath)) {
        New-Item -Path $registryPath -Force | Out-Null
    }
    Set-ItemProperty -Path $registryPath -Name "(Default)" -Value $finalManifestPath -Force
} catch {
    Write-Host "Error: Failed to register Native Host in registry. You might need to run this script as Administrator."
    Remove-Item $finalManifestPath -ErrorAction SilentlyContinue
    exit
}

# --- 8. Completion Message ---
Write-Host ""
Write-Host "========================================================="
Write-Host "Installation Complete!"
Write-Host "The Native Host '$nativeHostName' has been registered."
Write-Host "Guardian.exe, its DLLs, and manifest are located at: '$installPath'"
Write-Host "You can now load/reload the Chrome Extension."
Write-Host "========================================================="
Write-Host ""

Read-Host "Press Enter to continue..."