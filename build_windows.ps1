[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$ProjectRoot = (Resolve-Path -LiteralPath $PSScriptRoot).Path
$Python = Join-Path $ProjectRoot '.venv\Scripts\python.exe'
$Spec = Join-Path $ProjectRoot 'PacketLens.spec'
$OutputDirectory = Join-Path $ProjectRoot 'dist\PacketLens'
$Executable = Join-Path $OutputDirectory 'PacketLens.exe'
$Version = (& $Python -c "from packetlens import __version__; print(__version__)" | Select-Object -Last 1).Trim()
if (-not $Version) { throw 'Unable to determine the PacketLens version.' }
$ZipPath = Join-Path $ProjectRoot "PacketLens-v$Version-Windows-x64.zip"
$ChecksumPath = "$ZipPath.sha256"

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'PacketLens Windows builds must run on Windows.'
}
if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw "Expected virtual-environment Python was not found: $Python"
}
if (-not (Test-Path -LiteralPath $Spec -PathType Leaf)) {
    throw "PyInstaller specification was not found: $Spec"
}

Push-Location $ProjectRoot
try {
    & $Python -c "import struct,sys; assert struct.calcsize('P') * 8 == 64, 'A 64-bit Python environment is required'; print(sys.version)"
    if ($LASTEXITCODE -ne 0) { throw 'Python architecture validation failed.' }

    & $Python -m PyInstaller --version
    if ($LASTEXITCODE -ne 0) {
        throw 'PyInstaller is missing. Install requirements-build.txt into the existing virtual environment.'
    }

    Write-Host 'Running automated tests...'
    & $Python -m unittest discover -s tests
    if ($LASTEXITCODE -ne 0) { throw 'Automated tests failed; packaging was stopped.' }

    Write-Host 'Building PacketLens onedir distribution...'
    & $Python -m PyInstaller --clean --noconfirm $Spec
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller build failed.' }
    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        throw "Build completed without the expected executable: $Executable"
    }

    & $Python -c "from packetlens.distribution import assert_dependency_cleanup,assert_distribution_safe; assert_distribution_safe(r'$OutputDirectory'); assert_dependency_cleanup(r'$OutputDirectory')"
    if ($LASTEXITCODE -ne 0) { throw 'Distribution content validation failed.' }

    $ProbePath = Join-Path $env:TEMP ('packetlens-probe-' + [Guid]::NewGuid().ToString('N') + '.json')
    try {
        $Process = Start-Process -FilePath $Executable -ArgumentList @('--packaging-probe', $ProbePath) -Wait -PassThru -WindowStyle Hidden
        if ($Process.ExitCode -ne 0) { throw "Packaged startup probe failed with exit code $($Process.ExitCode)." }
        if (-not (Test-Path -LiteralPath $ProbePath -PathType Leaf)) { throw 'Packaged startup probe produced no result.' }
        $Probe = Get-Content -LiteralPath $ProbePath -Raw | ConvertFrom-Json
        if ($Probe.version -ne $Version -or -not $Probe.frozen -or $Probe.page_count -ne 5) {
            throw "Unexpected packaged startup result: $($Probe | ConvertTo-Json -Compress)"
        }
    }
    finally {
        if (Test-Path -LiteralPath $ProbePath) { Remove-Item -LiteralPath $ProbePath -Force }
    }

    if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
    if (Test-Path -LiteralPath $ChecksumPath) { Remove-Item -LiteralPath $ChecksumPath -Force }
    $ArchiveCreated = $false
    for ($Attempt = 1; $Attempt -le 3; $Attempt++) {
        try {
            Compress-Archive -LiteralPath $OutputDirectory -DestinationPath $ZipPath -CompressionLevel Optimal
            $ArchiveCreated = $true
            break
        }
        catch {
            if ($Attempt -eq 3) { throw }
            Write-Warning "Archive attempt $Attempt failed because a build file was temporarily busy; retrying once the handle settles."
            if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
            Start-Sleep -Seconds 1
        }
    }
    if (-not $ArchiveCreated) { throw 'Distribution archive was not created.' }
    $Hash = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -LiteralPath $ChecksumPath -Value "$Hash  $(Split-Path -Leaf $ZipPath)" -Encoding ascii

    $ExecutableSize = (Get-Item -LiteralPath $Executable).Length
    $ZipSize = (Get-Item -LiteralPath $ZipPath).Length
    Write-Host "Build complete: $OutputDirectory"
    Write-Host "Executable: $Executable ($ExecutableSize bytes)"
    Write-Host "Archive: $ZipPath ($ZipSize bytes)"
    Write-Host "SHA-256: $Hash"
}
finally {
    Pop-Location
}
