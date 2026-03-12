param(
    [string]$AppPath = "C:\Users\vikra\OneDrive\Documents\Playground\dist\CDriveCleaner.exe",
    [string]$ShortcutName = "C Drive Cleaner",
    [string]$IconPath = "C:\Users\vikra\OneDrive\Documents\Playground\assets\app.ico"
)

$startMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$shortcutDir = Join-Path $startMenu "C Drive Cleaner"
New-Item -Path $shortcutDir -ItemType Directory -Force | Out-Null

$shortcutPath = Join-Path $shortcutDir "$ShortcutName.lnk"
$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $AppPath
$shortcut.WorkingDirectory = Split-Path $AppPath
if (Test-Path $IconPath) {
    $shortcut.IconLocation = $IconPath
}
$shortcut.Save()

Write-Host "Shortcut created at $shortcutPath"
