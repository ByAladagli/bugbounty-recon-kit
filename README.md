# bugbounty-recon-kit

Uzman seviye otomatik ve yarı-otomatik Bug Bounty Reconnaissance & Triage pipeline'ı. 
Hedef: İzinli web varlıklarında (in-scope) yüksek sinyalli güvenlik açıkları keşfetmek, false-positive (yanlış pozitif) oranını en aza indirmek ve doğrulanabilir PoC (Proof of Concept) hazırlık sürecini hızlandırmak.

---

## 🚀 Mimari & Araç Zinciri (The Real Bug Bounty Stack)

| Aşama | Araçlar | İşlev |
|---|---|---|
| **1. Program & Scope** | `public-bugbounty-programs`, `bounty-targets-data` | Kapsam içi (in-scope) nakit ödüllü hedefleri belirleme |
| **2. Subdomain Keşfi** | `subfinder`, `amass` | Hızlı ve derin pasif DNS & subdomain haritalama |
| **3. Canlı Varlık Filtresi** | `httpx` | Canlı HTTP/HTTPS servisleri, durum kodları ve teknoloji tespiti |
| **4. Port & Servis Tespiti**| `naabu` | Kritik açık portları (80, 443, 8080, 8443, 3000, 9000 vb.) hızlı tarama |
| **5. Endpoint & Yol Keşfi** | `katana`, `waybackurls` | Aktif DOM crawler + Wayback Machine geçmiş API uç noktaları |
| **6. Zafiyet Taraması** | `nuclei` + `nuclei-templates` | Güncel CVE, SSRF, XSS, IDOR, path traversal ve misconfig şablonları |
| **7. Dizin / Endpoint Fuzzing** | `ffuf` | Gizli admin panelleri, unlisted API rotaları ve hassas dosyalar |
| **8. Triage & PoC Doğrulama** | `agent.py` (Python Asyncio) | Otomatik deduplication, risk derecelendirme ve Markdown raporlama |

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

### 1. Hedef Listesini Hazırlayın
`targets.txt` dosyasına taranacak ana domainleri ekleyin:
```text
example.com
sub.example.com
```

### 2. Pipeline'ı Çalıştırın

**Windows (PowerShell):**
```powershell
.\scripts\recon_pipeline.ps1 targets.txt
```

**Linux / macOS (Bash):**
```bash
chmod +x ./scripts/recon_pipeline.sh
./scripts/recon_pipeline.sh targets.txt
```

### 3. Triage ve Rapor Üretimi
Nuclei ve HTTP verilerini ayrıştırıp temiz bir PoC Markdown raporu almak için:
```bash
python scripts/agent.py --aggregate outputs
```
Oluşturulan rapor: `outputs/report.md`

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
