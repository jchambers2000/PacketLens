[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DistributionPath,
    [Parameter(Mandatory = $true)]
    [string]$ReplacementInternalPath
)

$ErrorActionPreference = 'Stop'
$Distribution = (Resolve-Path -LiteralPath $DistributionPath).Path
$Replacement = (Resolve-Path -LiteralPath $ReplacementInternalPath).Path
$Executable = Join-Path $Distribution 'PacketLens.exe'
if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
    throw "PacketLens.exe was not found in $Distribution"
}

$Files = @(
    'PySide6\Qt6Core.dll', 'PySide6\Qt6Gui.dll', 'PySide6\Qt6Widgets.dll',
    'PySide6\Qt6Svg.dll', 'PySide6\opengl32sw.dll',
    'PySide6\QtCore.pyd', 'PySide6\QtGui.pyd', 'PySide6\QtWidgets.pyd',
    'PySide6\pyside6.abi3.dll', 'shiboken6\Shiboken.pyd',
    'shiboken6\shiboken6.abi3.dll',
    'PySide6\plugins\platforms\qwindows.dll',
    'PySide6\plugins\styles\qmodernwindowsstyle.dll',
    'PySide6\plugins\iconengines\qsvgicon.dll',
    'PySide6\plugins\imageformats\qgif.dll',
    'PySide6\plugins\imageformats\qico.dll',
    'PySide6\plugins\imageformats\qjpeg.dll',
    'PySide6\plugins\imageformats\qsvg.dll',
    'PySide6\plugins\imageformats\qwebp.dll'
)

$TempRoot = Join-Path $env:TEMP ('packetlens-qt-replacement-' + [Guid]::NewGuid().ToString('N'))
$Clone = Join-Path $TempRoot 'PacketLens'
$Probe = Join-Path $TempRoot 'probe.json'
try {
    New-Item -ItemType Directory -Path $TempRoot | Out-Null
    Copy-Item -LiteralPath $Distribution -Destination $Clone -Recurse
    foreach ($Relative in $Files) {
        $Source = Join-Path $Replacement $Relative
        $Target = Join-Path (Join-Path $Clone '_internal') $Relative
        if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) {
            throw "Replacement file is missing: $Source"
        }
        if (-not (Test-Path -LiteralPath $Target -PathType Leaf)) {
            throw "Audited distribution file is missing: $Target"
        }
        Copy-Item -LiteralPath $Source -Destination $Target -Force
    }

    $Process = Start-Process -FilePath (Join-Path $Clone 'PacketLens.exe') `
        -ArgumentList @('--packaging-probe', $Probe) -Wait -PassThru -WindowStyle Hidden
    if ($Process.ExitCode -ne 0) {
        throw "Replacement startup probe failed with exit code $($Process.ExitCode)."
    }
    if (-not (Test-Path -LiteralPath $Probe -PathType Leaf)) {
        throw 'Replacement startup probe produced no result.'
    }
    $Result = Get-Content -LiteralPath $Probe -Raw | ConvertFrom-Json
    if (-not $Result.frozen -or $Result.page_count -ne 5) {
        throw "Unexpected replacement probe result: $($Result | ConvertTo-Json -Compress)"
    }
    $Result | ConvertTo-Json -Depth 4
}
finally {
    if (Test-Path -LiteralPath $TempRoot) {
        $ResolvedTemp = (Resolve-Path -LiteralPath $TempRoot).Path
        $ResolvedSystemTemp = (Resolve-Path -LiteralPath $env:TEMP).Path
        if ((Split-Path -Parent $ResolvedTemp) -ne $ResolvedSystemTemp) {
            throw "Refusing to remove unexpected temporary path: $ResolvedTemp"
        }
        Remove-Item -LiteralPath $ResolvedTemp -Recurse -Force
    }
}
