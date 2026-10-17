# bugbounty-recon-kit

Uzman seviye otomatik ve yarı-otomatik Bug Bounty Reconnaissance & Triage pipeline'ı. 
Hedef: İzinli web varlıklarında (in-scope) yüksek sinyalli güvenlik açıkları keşfetmek, false-positive (yanlış pozitif) oranını en aza indirmek ve doğrulanabilir PoC (Proof of Concept) hazırlık sürecini hızlandırmak.

---

## 🚀 Mimari & Araç Zinciri (The Complete 16-Tool Bug Bounty Stack)

Dünyada kabul görmüş 16 temel açık kaynak Bug Bounty projesinin birleşik entegrasyonu:

| Aşama | Araçlar & Projeler | İşlev |
|---|---|---|
| **1. Program & Scope** | `projectdiscovery/public-bugbounty-programs`, `arkadiyt/bounty-targets-data` | 800+ VDP & nakit ödüllü programdan otomatik in-scope hedef ayıklama (`fetch_targets.py`) |
| **2. Subdomain Keşfi** | `projectdiscovery/subfinder`, `OWASP/Amass` | Hızlı ve derin pasif DNS & ASN/CIDR subdomain haritalama |
| **3. Canlı Varlık Filtresi** | `projectdiscovery/httpx` | Canlı HTTP/HTTPS servisleri, HTTP durum kodları, HTML title ve teknoloji tespiti |
| **4. Port & Servis Tespiti**| `projectdiscovery/naabu` | Kritik açık portları (80, 443, 8080, 8443, 3000, 9000 vb.) yüksek hızda tarama |
| **5. Endpoint & Yol Keşfi** | `projectdiscovery/katana`, `tomnomnom/waybackurls` | Aktif DOM crawler + Wayback Machine tarihsel API ve rota keşfi (`all_endpoints.txt`) |
| **6. Hassas Parametre Triage** | `tomnomnom/gf` + `1ndianl33t/Gf-Patterns` | SSRF, IDOR, SQLi, RCE, LFI, Open Redirect ve XSS potansiyeli taşıyan parametreleri filtreleme |
| **7. Zafiyet Taraması** | `projectdiscovery/nuclei` + `nuclei-templates` | Güncel CVE, SSRF, XSS, misconfig ve kritik zafiyet şablonları |
| **8. Dizin / Endpoint Fuzzing** | `ffuf/ffuf`, `maurosoria/dirsearch` | Gizli admin panelleri, unlisted API rotaları ve hassas dosyalar (`.env`, `.git` vb.) |
| **9. SQLi Doğrulama** | `sqlmapproject/sqlmap` | SQL Injection aday parametreleri için otomatik doğrulama komutları |
| **10. Triage & PoC Raporu** | `agent.py` (Python Asyncio) | Parametre analizi, deduplication, önem derecelendirmesi ve HackerOne standardında Markdown raporu |
| **11. Bilgi & Metodoloji** | `nahamsec/Resources-for-Bug-Bounty`, `EdOverflow/bugbounty-cheatsheet` | Bug bounty metodolojisi ve hızlı doğrulama kontrol listeleri |

---

## ⚠️ Yasal ve Etik Sorumluluk Reddi (Disclaimer)

Bu repo ve içerisindeki otomasyon betikleri yalnızca **izinli Bug Bounty programlarında (HackerOne, Bugcrowd, Intigriti vb.) veya yazılı izin alınmış penetrasyon testlerinde** kullanılmak üzere tasarlanmıştır. İzin alınmamış herhangi bir sistem veya ağ üzerinde yetkisiz tarama yapmak yasa dışıdır.

---

## 📦 Kurulum

### Windows (Yerel PowerShell / Go)
Araçlar doğrudan Go ve Python üzerinden kurulabilir:
```powershell
# Go araçları
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest

# Nuclei şablonlarını güncelle
nuclei -ut

# Python bağımlılıkları
pip install -r requirements.txt
```

### Linux / Ubuntu
```bash
sudo apt update && sudo apt install -y git curl jq python3-pip
pip install -r requirements.txt
```

---

## 🎯 Kullanım

### 1. Kapsam ve Hedefleri Otomatik Çekin (Hedef Seçimi)
800+ halka açık programdan veya HackerOne / Bugcrowd nakit ödüllü in-scope hedeflerini tek komutla `targets.txt` dosyasına kaydedin:
```bash
# Örnek: GitLab programındaki in-scope domainleri çek
python scripts/fetch_targets.py --query gitlab --bounty-only -o targets.txt

# Örnek: Shopify hedeflerini çek
python scripts/fetch_targets.py --query shopify --bounty-only -o targets.txt
```
Veya `targets.txt` dosyasına manuel olarak ana domainleri ekleyin:
```text
example.com
sub.example.com
```

### 2. Pipeline'ı Çalıştırın

**Windows (PowerShell):**
```powershell
.\scripts\recon_pipeline.ps1 -TargetsFile targets.txt -OutputDir outputs
```

**Linux / macOS (Bash):**
```bash
chmod +x ./scripts/recon_pipeline.sh
./scripts/recon_pipeline.sh targets.txt outputs
```

### 3. Triage ve Rapor Üretimi
Boru hattı tamamlandığında `agent.py` otomatik olarak:
- Nuclei bulgularını derecelendirir,
- `gf` ile ayıklanan SSRF, IDOR, SQLi, RCE, LFI aday parametrelerini gruplar,
- `sqlmap` hazır doğrulama komutlarını ve `curl` PoC kanıtlarını oluşturur:
```bash
python scripts/agent.py --aggregate --outdir outputs
```
Oluşturulan nihai rapor: `outputs/report.md`

---

## 📂 Dosya Yapısı

```
bugbounty-recon-kit/
├── .github/
│   └── workflows/
│       └── dispatch-scan.yml      # Manuel GitHub Actions tetikleyicisi
├── scripts/
│   ├── recon_pipeline.ps1         # Windows PowerShell tam otomatik boru hattı
│   ├── recon_pipeline.sh          # Linux Bash tam otomatik boru hattı
│   └── agent.py                   # Asyncio doğrulama, filtreleme & PoC raporlayıcı
├── targets.example.txt            # Örnek hedef dosyası
├── requirements.txt               # Python gereksinimleri (aiohttp)
├── .gitignore
├── LICENSE
└── README.md
```

## 🛡️ Katkı & Lisans
MIT License. Katkıda bulunmak için PR açabilir veya özel Nuclei şablonlarınızı ekleyebilirsiniz.
