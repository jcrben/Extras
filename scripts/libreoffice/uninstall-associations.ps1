# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Output "Script is not running as Administrator. Restarting with elevated privileges..."
    Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Define the registry paths to remove
$pathsToRemove = @(
    "HKCU:\Software\Classes\Applications\soffice.exe\shell\open",
    "HKCU:\Software\Classes\LibreOffice.Calc",
    "HKCU:\Software\Classes\.ods",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ods\OpenWithList",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ods\OpenWithProgids",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ods\UserChoice",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OpenWithList\soffice.exe",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\OpenWithProgids\LibreOffice.Calc",
    "HKCR:\*\OpenWithList\soffice.exe",
    "HKCR:\*\OpenWithProgids\LibreOffice.Calc"
)

# Remove registry keys for the current user
foreach ($path in $pathsToRemove) {
    Remove-Item -Path $path -Force -Recurse -ErrorAction SilentlyContinue
}

# Get all user SIDs
$userSIDs = Get-ChildItem -Path "Registry::HKEY_USERS" | Where-Object { $_.Name -match "S-1-5-21-\d+-\d+-\d+-\d+$" }

# Remove registry keys for all users
foreach ($sid in $userSIDs) {
    $userPathsToRemove = @(
        "$($sid.PSPath)\Software\Classes\Applications\scalc.exe\shell\open\command"
    )
    foreach ($path in $userPathsToRemove) {
        Remove-Item -Path $path -Force -Recurse -ErrorAction SilentlyContinue
    }
}
