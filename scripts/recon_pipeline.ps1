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
    Write-Host "[3/9] Kritik portlar taranıyor (naabu)..." -ForegroundColor Yellow
    Get-Content $allSubs | & naabu -silent -p 80,443,8080,8443,3000,8000,8888,9000,5000,9090 -rate 100 -o $naabuPorts
}

# 5) Endpoint & Rota Keşfi (katana + waybackurls)
Write-Host "[4/9] Endpoint ve parametre keşfi (katana + waybackurls)..." -ForegroundColor Yellow
$katanaPaths = Join-Path $OutputDir "katana_paths.txt"
if (Get-Command katana -ErrorAction SilentlyContinue) {
    Get-Content $liveUrls | & katana -silent -jc -kf -d 2 -o $katanaPaths
}

$waybackPaths = Join-Path $OutputDir "wayback_paths.txt"
if (Get-Command waybackurls -ErrorAction SilentlyContinue) {
    Get-Content $allSubs | & waybackurls | Out-File -Encoding utf8 -FilePath $waybackPaths
}

# 5b) Rotaları Birleştir ve Tekilleştir
$allEndpoints = Join-Path $OutputDir "all_endpoints.txt"
$endpointsList = @()
if (Test-Path $katanaPaths) { $endpointsList += Get-Content $katanaPaths }
if (Test-Path $waybackPaths) { $endpointsList += Get-Content $waybackPaths }
$uniqueEndpoints = $endpointsList | Where-Object { $_ -match "^https?://" } | Sort-Object -Unique
$uniqueEndpoints | Out-File -Encoding utf8 -FilePath $allEndpoints
Write-Host "[✓] Toplam keşfedilen endpoint ve rota: $($uniqueEndpoints.Count)" -ForegroundColor Green

# 6) Hassas Parametre Ayıklama (gf patterns: SSRF, IDOR, SQLi, RCE, LFI, Redirect)
Write-Host "[5/9] Hassas parametreler ayıklanıyor (gf patterns)..." -ForegroundColor Yellow
$gfDir = Join-Path $OutputDir "gf_patterns"
New-Item -ItemType Directory -Force -Path $gfDir | Out-Null
if (Get-Command gf -ErrorAction SilentlyContinue -and (Test-Path $allEndpoints) -and (Get-Item $allEndpoints).Length -gt 0) {
    $gfPatterns = @("ssrf", "idor", "sqli", "rce", "lfi", "redirect", "xss", "ssti")
    foreach ($pat in $gfPatterns) {
        $outFile = Join-Path $gfDir "$pat.txt"
        Get-Content $allEndpoints | & gf $pat | Sort-Object -Unique | Out-File -Encoding utf8 -FilePath $outFile
        $patCount = if (Test-Path $outFile) { (Get-Content $outFile).Count } else { 0 }
        if ($patCount -gt 0) {
            Write-Host "    ↳ [!] $pat parametresi bulundu: $patCount adet ($outFile)" -ForegroundColor Magenta
        }
    }
}

# 7) Zafiyet Taraması (nuclei + templates)
Write-Host "[6/9] Template bazlı güvenlik denetimi yürütülüyor (nuclei)..." -ForegroundColor Yellow
$nucleiJson = Join-Path $OutputDir "nuclei.json"
$nucleiReadable = Join-Path $OutputDir "nuclei_readable.txt"

if (Get-Command nuclei -ErrorAction SilentlyContinue) {
    $nucleiTemplatesFlag = @()
    if (Test-Path "C:\Users\mehme\nuclei-templates") {
        $nucleiTemplatesFlag = @("-t", "C:\Users\mehme\nuclei-templates")
    }
    & nuclei -l $liveUrls -s critical,high,medium -c $Concurrency @nucleiTemplatesFlag -json-export $nucleiJson -o $nucleiReadable -silent
    Write-Host "[✓] Nuclei taraması tamamlandı." -ForegroundColor Green
}

# 8) Fuzzing & Dizin Keşfi (ffuf + dirsearch)
Write-Host "[7/9] Gizli admin ve hassas dosya fuzzing (ffuf / dirsearch)..." -ForegroundColor Yellow
$ffufResults = Join-Path $OutputDir "ffuf_results.json"
if (Get-Command ffuf -ErrorAction SilentlyContinue -and (Test-Path $liveUrls)) {
    $firstTarget = (Get-Content $liveUrls | Select-Object -First 1)
    if ($firstTarget) {
        $tempWordlist = Join-Path $OutputDir "temp_wordlist.txt"
        @(".env", "admin", "api", "swagger.json", "actuator/health", ".git/HEAD", "wp-login.php", "console") | Out-File -Encoding utf8 $tempWordlist
        & ffuf -u "$firstTarget/FUZZ" -w $tempWordlist -mc 200,301,302,401,403 -silent -o $ffufResults
        Remove-Item $tempWordlist -ErrorAction SilentlyContinue
    }
}

# 9) SQLi Doğrulama Adayları Kontrolü (sqlmap referansı)
$sqliFile = Join-Path $gfDir "sqli.txt"
if (Test-Path $sqliFile) {
    $sqliCandidates = Get-Content $sqliFile | Where-Object { $_ -match "\?" } | Select-Object -First 5
    if ($sqliCandidates) {
        Write-Host "[8/9] SQLi aday parametreleri tespit edildi. sqlmap doğrulaması hazırlandı." -ForegroundColor Yellow
        $sqlmapCmds = Join-Path $OutputDir "sqlmap_commands.txt"
        $sqliCandidates | ForEach-Object { "sqlmap -u `"$_`" --batch --dbs --random-agent" } | Out-File -Encoding utf8 -FilePath $sqlmapCmds
    }
}

# 10) Triage & Rapor Üretimi (agent.py)
Write-Host "[9/9] Sonuçlar ayıklanıyor ve PoC raporu üretiliyor (agent.py)..." -ForegroundColor Yellow
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$agentPy = Join-Path $scriptDir "agent.py"
python $agentPy --outdir $OutputDir

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "✅ Pipeline başarıyla tamamlandı!" -ForegroundColor Green
Write-Host "📄 Üretilen Triage Raporu: $OutputDir\report.md" -ForegroundColor Cyan
Write-Host "=================================================================="
