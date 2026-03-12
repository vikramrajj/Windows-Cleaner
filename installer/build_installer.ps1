param(
    [string]$WixBin = ""
)

$root = Split-Path -Parent $PSScriptRoot
$spec = Join-Path $root "cleaner.spec"
$distExe = Join-Path $root "dist\CDriveCleaner.exe"
$icon = Join-Path $root "assets\app.ico"

if (-not (Test-Path $icon)) {
    Write-Error "Missing icon: $icon. Add assets\\app.ico before building."
    exit 1
}

if (-not (Test-Path $distExe)) {
    Write-Host "Building exe with PyInstaller..."
    pyinstaller $spec
}

$wixCandidates = @()
if ($WixBin) {
    $wixCandidates += $WixBin
}
$wixCandidates += "C:\Program Files (x86)\WiX Toolset v3.14\bin"
$wixCandidates += "C:\Program Files (x86)\WiX Toolset v3.11\bin"

$resolvedWix = $null
foreach ($candidate in $wixCandidates) {
    if (Test-Path (Join-Path $candidate "candle.exe")) {
        $resolvedWix = $candidate
        break
    }
}

if (-not $resolvedWix) {
    Write-Error "WiX not found. Install WiX Toolset and try again."
    exit 1
}

$candle = Join-Path $resolvedWix "candle.exe"
$light = Join-Path $resolvedWix "light.exe"
$wxs = Join-Path $PSScriptRoot "Product.wxs"
$out = Join-Path $PSScriptRoot "CDriveCleaner.msi"

& $candle $wxs -o "$PSScriptRoot\Product.wixobj"
& $light "$PSScriptRoot\Product.wixobj" -o $out

Write-Host "MSI created at $out"
