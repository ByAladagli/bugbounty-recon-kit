<#
==============================================================================
bugbounty-recon-kit: Complete Windows PowerShell Reconnaissance Pipeline
Usage: .\scripts\recon_pipeline.ps1 [-TargetsFile targets.txt] [-OutputDir outputs]
==============================================================================
#>
[CmdletBinding()]
param (
    [string]$TargetsFile = "targets.txt",
    [string]$OutputDir = "outputs",
    [int]$Concurrency = 30
)

$ErrorActionPreference = "Continue"

if (-not (Test-Path $TargetsFile)) {
    Write-Host "[-] Hata: Hedef dosyası bulunamadı: $TargetsFile" -ForegroundColor Red
    Write-Host "    Örnek: 'example.com' | Out-File -Encoding utf8 targets.txt"
    exit 1
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "🎯 Bug Bounty Recon Pipeline Başlatılıyor (Windows / PowerShell)" -ForegroundColor Cyan
Write-Host "Hedef Dosyası: $TargetsFile"
Write-Host "Çıktı Dizini:  $OutputDir"
Write-Host "=================================================================="

# 1) Subdomain Keşfi (subfinder + amass)
Write-Host "[1/7] Subdomain keşfi yürütülüyor (subfinder)..." -ForegroundColor Yellow
$subfinderOut = Join-Path $OutputDir "subfinder.txt"
if (Get-Command subfinder -ErrorAction SilentlyContinue) {
    & subfinder -dL $TargetsFile -silent -o $subfinderOut
} else {
    New-Item -ItemType File -Force -Path $subfinderOut | Out-Null
}

$amassOut = Join-Path $OutputDir "amass.txt"
if (Get-Command amass -ErrorAction SilentlyContinue) {
    Write-Host "[1/7b] Derin pasif keşif (amass)..." -ForegroundColor Yellow
    & amass enum -passive -df $TargetsFile -o $amassOut 2>$null
} else {
    New-Item -ItemType File -Force -Path $amassOut | Out-Null
}

# 2) Birleştir ve Tekilleştir
$allSubs = Join-Path $OutputDir "all_subs.txt"
$subsList = @()
if (Test-Path $subfinderOut) { $subsList += Get-Content $subfinderOut }
if (Test-Path $amassOut) { $subsList += Get-Content $amassOut }
if (Test-Path $TargetsFile) { $subsList += Get-Content $TargetsFile }

$uniqueSubs = $subsList | Where-Object { $_ -and -not $_.StartsWith("#") } | Sort-Object -Unique
$uniqueSubs | Out-File -Encoding utf8 -FilePath $allSubs
Write-Host "[✓] Toplam keşfedilen subdomain: $($uniqueSubs.Count)" -ForegroundColor Green

# 3) Canlı Servis Filtresi (httpx)
Write-Host "[2/7] Canlı HTTP/HTTPS servisleri taranıyor (httpx)..." -ForegroundColor Yellow
$httpxLive = Join-Path $OutputDir "httpx_live.txt"
$liveUrls = Join-Path $OutputDir "live_urls.txt"

if (Get-Command httpx -ErrorAction SilentlyContinue) {
    Get-Content $allSubs | & httpx -silent -threads $Concurrency -status-code -title -tech-detect -o $httpxLive
    if (Test-Path $httpxLive) {
        $liveList = Get-Content $httpxLive | ForEach-Object { ($_ -split '\s+')[0] } | Where-Object { $_ -match "^http" }
        $liveList | Out-File -Encoding utf8 -FilePath $liveUrls
    }
}

if (-not (Test-Path $liveUrls) -or (Get-Item $liveUrls).Length -eq 0) {
    $uniqueSubs | ForEach-Object { "https://$_" } | Out-File -Encoding utf8 -FilePath $liveUrls
}
$liveCount = (Get-Content $liveUrls).Count
Write-Host "[✓] Toplam canlı HTTP servisi: $liveCount" -ForegroundColor Green

# 4) Port ve Servis Tespiti (naabu)
$naabuPorts = Join-Path $OutputDir "naabu_ports.txt"
if (Get-Command naabu -ErrorAction SilentlyContinue) {
    Write-Host "[3/7] Kritik portlar taranıyor (naabu)..." -ForegroundColor Yellow
    Get-Content $allSubs | & naabu -silent -p 80,443,8080,8443,3000,8000,8888,9000,5000,9090 -rate 100 -o $naabuPorts
}

# 5) Endpoint & Rota Keşfi (katana)
$katanaPaths = Join-Path $OutputDir "katana_paths.txt"
if (Get-Command katana -ErrorAction SilentlyContinue) {
    Write-Host "[4/7] Endpoint ve parametre keşfi (katana)..." -ForegroundColor Yellow
    Get-Content $liveUrls | & katana -silent -jc -kf -d 2 -o $katanaPaths
}

# 6) Zafiyet Taraması (nuclei)
Write-Host "[5/7] Template bazlı güvenlik denetimi yürütülüyor (nuclei)..." -ForegroundColor Yellow
$nucleiJson = Join-Path $OutputDir "nuclei.json"
$nucleiReadable = Join-Path $OutputDir "nuclei_readable.txt"

if (Get-Command nuclei -ErrorAction SilentlyContinue) {
    & nuclei -l $liveUrls -s critical,high,medium -c $Concurrency -json-export $nucleiJson -o $nucleiReadable -silent
    Write-Host "[✓] Nuclei taraması tamamlandı." -ForegroundColor Green
}

# 7) Fuzzing (ffuf)
$ffufResults = Join-Path $OutputDir "ffuf_results.json"
if (Get-Command ffuf -ErrorAction SilentlyContinue -and (Test-Path $liveUrls)) {
    Write-Host "[6/7] Gizli admin ve hassas dosya fuzzing (ffuf)..." -ForegroundColor Yellow
    $firstTarget = (Get-Content $liveUrls | Select-Object -First 1)
    if ($firstTarget) {
        $tempWordlist = Join-Path $OutputDir "temp_wordlist.txt"
        @(".env", "admin", "api", "swagger.json", "actuator/health", ".git/HEAD", "wp-login.php", "console") | Out-File -Encoding utf8 $tempWordlist
        & ffuf -u "$firstTarget/FUZZ" -w $tempWordlist -mc 200,301,302,401,403 -silent -o $ffufResults
        Remove-Item $tempWordlist -ErrorAction SilentlyContinue
    }
}

# 8) Triage & Rapor Üretimi (agent.py)
Write-Host "[7/7] Sonuçlar ayıklanıyor ve PoC raporu üretiliyor (agent.py)..." -ForegroundColor Yellow
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentPy = Join-Path $scriptDir "agent.py"
python $agentPy --outdir $OutputDir

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "✅ Pipeline başarıyla tamamlandı!" -ForegroundColor Green
Write-Host "📄 Üretilen Triage Raporu: $OutputDir\report.md" -ForegroundColor Cyan
Write-Host "=================================================================="
