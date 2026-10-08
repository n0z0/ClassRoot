[CmdletBinding()]
param (
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\ClassRoot"
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " ClassRoot WebRTC Decoy Installer (Win)   " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

# 1. Tentukan tag rilis
$Repo = "n0z0/ClassRoot"
if ($Version -eq "latest") {
    Write-Host "[*] Memeriksa rilis terbaru dari GitHub..." -ForegroundColor Yellow
    try {
        $ReleaseUrl = "https://api.github.com/repos/$Repo/releases/latest"
        $Release = Invoke-RestMethod -Uri $ReleaseUrl -Headers @{ "User-Agent" = "PowerShell" }
        $TargetTag = $Release.tag_name
    } catch {
        Write-Error "Gagal mendapatkan metadata rilis terbaru: $_"
    }
} else {
    if (-not $Version.StartsWith("v")) {
        $TargetTag = "v" + $Version
    } else {
        $TargetTag = $Version
    }
}

Write-Host "[*] Target versi: $TargetTag" -ForegroundColor Green

# 2. Cek apakah versi sudah terpasang
$CurrentExe = Join-Path $InstallDir "classroot.exe"
if (Test-Path $CurrentExe) {
    try {
        $InstalledVer = (& $CurrentExe -version 2>&1).Trim()
        Write-Host "[*] Versi terpasang saat ini: $InstalledVer" -ForegroundColor Cyan
        if ($InstalledVer -like "*$TargetTag*") {
            Write-Host "[OK] ClassRoot sudah berada pada versi terbaru ($TargetTag)." -ForegroundColor Green
            Write-Host "    Lokasi: $CurrentExe"
            $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
            if ($UserPath -notlike "*$InstallDir*") {
                $UpdatedPath = $UserPath.TrimEnd(';') + ';' + $InstallDir
                [Environment]::SetEnvironmentVariable("Path", $UpdatedPath, "User")
                $env:Path = "$env:Path;$InstallDir"
                Write-Host "[OK] PATH berhasil ditambahkan." -ForegroundColor Green
            }
            return
        }
    } catch {}
}

# 3. Download dan pasang bundel release
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$ZipName = "classroot_" + $TargetTag + "_windows_amd64.zip"
$ZipUrl = "https://github.com/$Repo/releases/download/$TargetTag/$ZipName"
$TempZip = Join-Path $env:TEMP $ZipName
$TempExtract = Join-Path $env:TEMP ("classroot_ext_" + [Guid]::NewGuid().ToString('N'))

Write-Host "[*] Mengunduh bundel rilis dari $ZipUrl ..." -ForegroundColor Yellow
$Downloaded = $false

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $ZipUrl -OutFile $TempZip -UseBasicParsing
    Expand-Archive -Path $TempZip -DestinationPath $TempExtract -Force

    # Salin seluruh isi folder hasil ekstrak ke direktori instalasi
    $ExtractedSub = Get-ChildItem -Path $TempExtract | Where-Object { $_.PSIsContainer } | Select-Object -First 1
    $SourcePath = if ($ExtractedSub) { $ExtractedSub.FullName } else { $TempExtract }

    Copy-Item -Path "$SourcePath\*" -Destination $InstallDir -Recurse -Force
    $Downloaded = $true
} catch {
    Write-Host "[*] Gagal mengunduh/ekstrak zip, mencoba unduh binary langsung..." -ForegroundColor Gray
    $DirectExeUrl = "https://github.com/$Repo/releases/download/$TargetTag/classroot_windows_amd64.exe"
    $TargetExePath = Join-Path $InstallDir "classroot.exe"
    try {
        Invoke-WebRequest -Uri $DirectExeUrl -OutFile $TargetExePath -UseBasicParsing
        $Downloaded = $true
    } catch {
        Write-Error "Gagal mengunduh ClassRoot dari GitHub: $_"
    }
} finally {
    Remove-Item -Path $TempZip -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $TempExtract -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $Downloaded) {
    Write-Error "Gagal memasang binary ClassRoot."
}

# 4. Daftarkan ke PATH User
$UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($UserPath -notlike "*$InstallDir*") {
    Write-Host "[*] Menambahkan $InstallDir ke PATH pengguna..." -ForegroundColor Yellow
    $UpdatedPath = $UserPath.TrimEnd(';') + ';' + $InstallDir
    [Environment]::SetEnvironmentVariable("Path", $UpdatedPath, "User")
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "[OK] Direktori berhasil ditambahkan ke PATH!" -ForegroundColor Green
} else {
    Write-Host "[*] Direktori sudah ada di PATH." -ForegroundColor Gray
}

# 5. Selesai
$InstalledExe = Join-Path $InstallDir "classroot.exe"
Write-Host "==========================================" -ForegroundColor Green
Write-Host " Sukses! ClassRoot Decoy berhasil dipasang." -ForegroundColor Green
Write-Host " Versi: $TargetTag" -ForegroundColor Green
Write-Host " Lokasi: $InstalledExe" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host "Buka terminal baru dan jalankan (HTTPS bawaan dengan auto-cert):"
Write-Host '   classroot -http :8443' -ForegroundColor Yellow
