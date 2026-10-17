#!/usr/bin/env bash
# ==============================================================================
# bugbounty-recon-kit: Complete Linux/macOS Reconnaissance Pipeline
# Usage: ./recon_pipeline.sh [targets.txt] [output_dir]
# ==============================================================================
set -euo pipefail

TARGETS_FILE="${1:-targets.txt}"
OUTDIR="${2:-outputs}"
CONCURRENCY=40

mkdir -p "$OUTDIR"

if [ ! -f "$TARGETS_FILE" ]; then
  echo "[-] Hata: Hedef dosyası bulunamadı: $TARGETS_FILE"
  echo "    Örnek: echo 'example.com' > targets.txt"
  exit 1
fi

echo "=================================================================="
echo "🎯 Bug Bounty Recon Pipeline Başlatılıyor"
echo "Hedef Dosyası: $TARGETS_FILE"
echo "Çıktı Dizini:  $OUTDIR"
echo "=================================================================="

# 1) Pasif ve Hızlı Subdomain Keşfi (subfinder + amass)
echo "[1/7] Subdomain keşfi yürütülüyor (subfinder)..."
if command -v subfinder >/dev/null 2>&1; then
  subfinder -dL "$TARGETS_FILE" -silent -o "$OUTDIR/subfinder.txt" || true
else
  echo "[!] subfinder bulunamadı, atlanıyor."
  touch "$OUTDIR/subfinder.txt"
fi

if command -v amass >/dev/null 2>&1; then
  echo "[1/7b] Derin pasif keşif (amass)..."
  amass enum -passive -df "$TARGETS_FILE" -o "$OUTDIR/amass.txt" 2>/dev/null || true
else
  touch "$OUTDIR/amass.txt"
fi

# 2) Birleştir ve Tekilleştir
cat "$OUTDIR/subfinder.txt" "$OUTDIR/amass.txt" "$TARGETS_FILE" | sort -u | grep -v "^#" | grep -v "^$" > "$OUTDIR/all_subs.txt"
TOTAL_SUBS=$(wc -l < "$OUTDIR/all_subs.txt")
echo "[✓] Toplam keşfedilen subdomain: $TOTAL_SUBS"

# 3) Canlı Servis Filtresi (httpx)
echo "[2/7] Canlı HTTP/HTTPS servisleri taranıyor (httpx)..."
if command -v httpx >/dev/null 2>&1; then
  cat "$OUTDIR/all_subs.txt" | httpx -silent -threads $CONCURRENCY -status-code -title -tech-detect -o "$OUTDIR/httpx_live.txt" || true
else
  echo "[!] httpx bulunamadı, ham subdomainler kullanılıyor."
  cp "$OUTDIR/all_subs.txt" "$OUTDIR/httpx_live.txt"
fi

# Canlı URL listesini çıkar
cat "$OUTDIR/httpx_live.txt" | awk '{print $1}' | grep "^http" > "$OUTDIR/live_urls.txt" || cp "$OUTDIR/all_subs.txt" "$OUTDIR/live_urls.txt"
TOTAL_LIVE=$(wc -l < "$OUTDIR/live_urls.txt")
echo "[✓] Toplam canlı HTTP servisi: $TOTAL_LIVE"

# 4) Port ve Servis Tespiti (naabu)
if command -v naabu >/dev/null 2>&1; then
  echo "[3/7] Kritik portlar taranıyor (naabu)..."
  cat "$OUTDIR/all_subs.txt" | naabu -silent -p 80,443,8080,8443,3000,8000,8888,9000,5000,9090 -rate 100 -o "$OUTDIR/naabu_ports.txt" || true
fi

# 5) Endpoint & Rota Keşfi (katana & waybackurls)
echo "[4/9] Endpoint ve parametre keşfi (katana & waybackurls)..."
if command -v katana >/dev/null 2>&1; then
  cat "$OUTDIR/live_urls.txt" | katana -silent -jc -kf -d 2 -o "$OUTDIR/katana_paths.txt" || true
fi

if command -v waybackurls >/dev/null 2>&1; then
  echo "[4/9b] Tarihsel Wayback Machine rotaları çekiliyor..."
  cat "$OUTDIR/all_subs.txt" | waybackurls | sort -u > "$OUTDIR/wayback_paths.txt" || true
fi

# 5b) Rotaları Birleştir ve Tekilleştir
cat "$OUTDIR/katana_paths.txt" "$OUTDIR/wayback_paths.txt" 2>/dev/null | grep -E "^https?://" | sort -u > "$OUTDIR/all_endpoints.txt" || true
TOTAL_ENDPOINTS=$(wc -l < "$OUTDIR/all_endpoints.txt" 2>/dev/null || echo 0)
echo "[✓] Toplam keşfedilen endpoint ve rota: $TOTAL_ENDPOINTS"

# 6) Hassas Parametre Ayıklama (gf patterns)
echo "[5/9] Hassas parametreler ayıklanıyor (gf patterns)..."
mkdir -p "$OUTDIR/gf_patterns"
if command -v gf >/dev/null 2>&1 && [ -s "$OUTDIR/all_endpoints.txt" ]; then
  for pat in ssrf idor sqli rce lfi redirect xss ssti; do
    cat "$OUTDIR/all_endpoints.txt" | gf "$pat" 2>/dev/null | sort -u > "$OUTDIR/gf_patterns/$pat.txt" || true
    COUNT=$(wc -l < "$OUTDIR/gf_patterns/$pat.txt" 2>/dev/null || echo 0)
    if [ "$COUNT" -gt 0 ]; then
      echo "    ↳ [!] $pat parametresi bulundu: $COUNT adet ($OUTDIR/gf_patterns/$pat.txt)"
    fi
  done
fi

# 7) Zafiyet Taraması (nuclei)
echo "[6/9] Template bazlı güvenlik denetimi yürütülüyor (nuclei)..."
if command -v nuclei >/dev/null 2>&1; then
  nuclei -l "$OUTDIR/live_urls.txt" \
         -s critical,high,medium \
         -c $CONCURRENCY \
         -json-export "$OUTDIR/nuclei.json" \
         -o "$OUTDIR/nuclei_readable.txt" \
         -silent || true
  echo "[✓] Nuclei taraması tamamlandı."
else
  echo "[!] nuclei kurulu değil, atlanıyor."
fi

# 8) Fuzzing (ffuf)
if command -v ffuf >/dev/null 2>&1 && [ -f "$OUTDIR/live_urls.txt" ]; then
  echo "[7/9] Gizli admin ve hassas dosya fuzzing (ffuf)..."
  SAMPLE_TARGET=$(head -n 1 "$OUTDIR/live_urls.txt" || true)
  if [ -n "$SAMPLE_TARGET" ]; then
    ffuf -u "${SAMPLE_TARGET}/FUZZ" \
         -w <(echo -e ".env\nadmin\napi\nswagger.json\nactuator/health\n.git/HEAD\nwp-login.php\nconsole") \
         -mc 200,301,302,401,403 \
         -silent \
         -o "$OUTDIR/ffuf_results.json" || true
  fi
fi

# 9) SQLi Doğrulama Adayları (sqlmap referansı)
if [ -s "$OUTDIR/gf_patterns/sqli.txt" ]; then
  echo "[8/9] SQLi aday parametreleri tespit edildi. sqlmap doğrulaması hazırlanıyor..."
  grep "?" "$OUTDIR/gf_patterns/sqli.txt" | head -n 5 | while read -r line; do
    echo "sqlmap -u \"$line\" --batch --dbs --random-agent"
  done > "$OUTDIR/sqlmap_commands.txt"
fi

# 10) Triage & Rapor Üretimi (agent.py)
echo "[9/9] Sonuçlar ayıklanıyor ve PoC raporu üretiliyor (agent.py)..."
python3 "$(dirname "$0")/agent.py" --outdir "$OUTDIR"

echo "=================================================================="
echo "✅ Pipeline başarıyla tamamlandı!"
echo "📄 Üretilen Triage Raporu: $OUTDIR/report.md"
echo "=================================================================="
