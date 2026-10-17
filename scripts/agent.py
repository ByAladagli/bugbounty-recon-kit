#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bugbounty-recon-kit Orchestrator & Triage Agent:
Parses tool outputs (Nuclei, HTTPx, Katana, FFUF), validates endpoints,
removes duplicate signals, ranks findings by severity, and generates structured PoC dossiers.
"""
import argparse
import asyncio
import json
import os
import sys
import time
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional

try:
    if sys.stdout.encoding != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding != "utf-8":
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

try:
    import aiohttp
except ImportError:
    aiohttp = None

CONCURRENCY = 30
TIMEOUT = 12


async def fetch_head(session: Any, url: str) -> Dict[str, Any]:
    """Lightweight HEAD request to verify if endpoint is alive and responsive."""
    try:
        async with session.head(url, timeout=TIMEOUT, allow_redirects=True) as resp:
            return {
                "url": url,
                "status": resp.status,
                "server": resp.headers.get("Server", ""),
                "content_type": resp.headers.get("Content-Type", ""),
                "alive": resp.status < 500
            }
    except Exception as e:
        return {"url": url, "alive": False, "error": str(e)}


async def validate_targets(targets: List[str], out_file: str) -> List[Dict[str, Any]]:
    """Validates targets asynchronously with concurrency limit."""
    if not aiohttp:
        print("[!] aiohttp not installed. Please install requirements: pip install aiohttp")
        return []

    sem = asyncio.Semaphore(CONCURRENCY)
    async with aiohttp.ClientSession() as session:
        async def worker(u: str):
            async with sem:
                clean_u = u.strip()
                if not clean_u.startswith("http"):
                    clean_u = "https://" + clean_u
                return await fetch_head(session, clean_u)

        tasks = [asyncio.create_task(worker(t)) for t in targets if t.strip()]
        results = await asyncio.gather(*tasks)

    os.makedirs(os.path.dirname(os.path.abspath(out_file)), exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    return results


def parse_nuclei_json(nuclei_json_path: str) -> List[Dict[str, Any]]:
    """Parses newline-delimited JSON output from Nuclei scanner."""
    findings = []
    if not os.path.exists(nuclei_json_path):
        return findings

    with open(nuclei_json_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            try:
                data = json.loads(line_str)
                findings.append(data)
            except Exception:
                continue
    return findings


def rank_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Deduplicates and ranks findings by severity (Critical -> High -> Medium -> Low -> Info)."""
    sev_map = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
        "unknown": 0
    }

    seen_keys = set()
    deduped = []

    for f in findings:
        info = f.get("info", {})
        template_id = info.get("template-id") or f.get("template-id", "unknown")
        matched_url = f.get("matched-at") or f.get("matched", "")
        dedup_key = f"{template_id}:{matched_url}"

        if dedup_key not in seen_keys:
            seen_keys.add(dedup_key)
            deduped.append(f)

    ranked = sorted(
        deduped,
        key=lambda item: sev_map.get(item.get("info", {}).get("severity", "info").lower(), 0),
        reverse=True
    )
    return ranked


def generate_markdown_report(findings: List[Dict[str, Any]], out_md: str, outdir: str = "") -> str:
    """Generates a professional Bug Bounty Recon & Triage Dossier in Markdown format."""
    now = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    os.makedirs(os.path.dirname(os.path.abspath(out_md)), exist_ok=True)

    with open(out_md, "w", encoding="utf-8") as f:
        f.write("# 🎯 Bug Bounty Reconnaissance & Triage Report\n\n")
        f.write(f"- **Tarih:** {now}\n")
        f.write(f"- **Toplam Benzersiz Nuclei Bulgusu:** {len(findings)}\n")

        # Summary statistics
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for fi in findings:
            sev = fi.get("info", {}).get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1

        f.write("### 📊 Bulguların Önem Seviyesi Dağılımı (Nuclei)\n")
        f.write(f"| Seviye | Sayı |\n|---|---|\n")
        f.write(f"| 🔴 Critical (P1) | {counts['critical']} |\n")
        f.write(f"| 🟠 High (P2) | {counts['high']} |\n")
        f.write(f"| 🟡 Medium (P3) | {counts['medium']} |\n")
        f.write(f"| 🔵 Low (P4) | {counts['low']} |\n")
        f.write(f"| ⚪ Informational (P5) | {counts['info']} |\n\n")

        # 1. Attack Surface Overview (naabu + endpoints)
        if outdir and os.path.exists(outdir):
            all_endpoints_file = os.path.join(outdir, "all_endpoints.txt")
            naabu_file = os.path.join(outdir, "naabu_ports.txt")

            f.write("### 🌐 Saldırı Yüzeyi ve Keşif Özeti\n")
            if os.path.exists(all_endpoints_file):
                with open(all_endpoints_file, "r", encoding="utf-8", errors="replace") as ef:
                    ep_lines = [l.strip() for l in ef if l.strip()]
                f.write(f"- **Katana & Waybackurls ile Keşfedilen Rotalar:** `{len(ep_lines)}` adet URL\n")

            if os.path.exists(naabu_file):
                with open(naabu_file, "r", encoding="utf-8", errors="replace") as nf:
                    ports = [l.strip() for l in nf if l.strip()]
                f.write(f"- **Naabu ile Tespit Edilen Açık Portlar:** `{len(ports)}` adet\n")
                if ports:
                    f.write(f"  ↳ `{', '.join(ports[:10])}`" + ("..." if len(ports) > 10 else "") + "\n")
            f.write("\n---\n\n")

        # 2. High-Impact Attack Vectors (gf patterns: SSRF, IDOR, SQLi, RCE, LFI, Redirect)
        if outdir and os.path.exists(os.path.join(outdir, "gf_patterns")):
            gf_dir = os.path.join(outdir, "gf_patterns")
            vector_titles = {
                "ssrf": ("🚨 Server-Side Request Forgery (SSRF) Aday Parametreleri", "P1-P2", "Cloud metadata (169.254.169.254) veya dahili ağ erişimi test edilmeli"),
                "idor": ("🔑 IDOR / BOLA Yetkisiz Erişim Aday Parametreleri", "P1-P3", "Farklı kullanıcı oturumuyla hesap kimliği değiştirilip test edilmeli"),
                "sqli": ("💉 SQL Injection Aday Parametreleri", "P1-P2", "Tek tırnak (') ve boolean farkları test edilmeli"),
                "rce": ("⚡ Remote Code Execution (RCE) / Komut Enjeksiyonu", "P1", "Kullanıcı girdisinin sistem komutuna gitme riski"),
                "lfi": ("📂 Local / Remote File Inclusion (LFI/RFI)", "P2-P3", "../../../etc/passwd veya dahili dosya yolu sızıntısı"),
                "redirect": ("🔀 Açık Yönlendirme (Open Redirect)", "P4", "OAuth2 login akışlarında token çalma zinciri için kritik"),
                "xss": ("💥 Cross-Site Scripting (XSS) Aday Parametreleri", "P3-P4", "Tarayıcıda kontrolsüz yansıtılan parametreler")
            }

            f.write("## 🎯 Yüksek Ödül Değerli Saldırı Vektörleri (Gf-Patterns Triage)\n\n")
            f.write("> Bu parametreler Katana crawler ve Wayback Machine rotalarından ayıklanmış, gerçek ödül getiren açık sınıflarıdır.\n\n")

            for vec, (v_title, v_sev, v_desc) in vector_titles.items():
                vf = os.path.join(gf_dir, f"{vec}.txt")
                if os.path.exists(vf):
                    with open(vf, "r", encoding="utf-8", errors="replace") as v_in:
                        urls = [l.strip() for l in v_in if l.strip()]
                    if urls:
                        f.write(f"### {v_title} (`{v_sev}`)\n")
                        f.write(f"- **Açıklama:** {v_desc}\n")
                        f.write(f"- **Tespit Edilen URL Sayısı:** `{len(urls)}`\n")
                        f.write("- **Örnek Hedefler:**\n")
                        for u in urls[:5]:
                            f.write(f"  - `{u}`\n")
                        f.write("\n")

            # Check sqlmap commands
            sqlmap_file = os.path.join(outdir, "sqlmap_commands.txt")
            if os.path.exists(sqlmap_file):
                with open(sqlmap_file, "r", encoding="utf-8", errors="replace") as sf:
                    cmds = [l.strip() for l in sf if l.strip()]
                if cmds:
                    f.write("### 🧪 Otomatik SQLi Doğrulama Komutları (sqlmap)\n")
                    f.write("```bash\n")
                    for c in cmds[:3]:
                        f.write(f"{c}\n")
                    f.write("```\n\n")

            f.write("---\n\n")

        # 3. Nuclei Findings Detail
        f.write("## 🔍 Doğrulanmış Güvenlik Zafiyetleri (Nuclei)\n\n")
        if not findings:
            f.write("> [!NOTE]\n> Nuclei taramasında doğrulanmış aktif zafiyet tespit edilmedi. Saldırı yüzeyi temiz görünüyor.\n")
            return out_md

        for i, fi in enumerate(findings, 1):
            info = fi.get("info", {})
            name = info.get("name", "Unnamed Finding")
            severity = info.get("severity", "INFO").upper()
            template_id = fi.get("template-id", info.get("template-id", "n/a"))
            host = fi.get("host", "")
            matched_at = fi.get("matched-at") or fi.get("matched", "")
            cve_ids = info.get("classification", {}).get("cve-id", [])
            cwe_ids = info.get("classification", {}).get("cwe-id", [])
            cvss_score = info.get("classification", {}).get("cvss-score", "N/A")

            f.write(f"### {i}. [{severity}] {name}\n\n")
            f.write(f"- **Hedef Host:** `{host}`\n")
            f.write(f"- **Eşleşen URL / Endpoint:** `{matched_at}`\n")
            f.write(f"- **Nuclei Şablonu:** `{template_id}`\n")
            if cvss_score != "N/A":
                f.write(f"- **CVSS Skoru:** `{cvss_score}`\n")
            if cve_ids:
                f.write(f"- **CVE:** `{', '.join(cve_ids) if isinstance(cve_ids, list) else cve_ids}`\n")
            if cwe_ids:
                f.write(f"- **CWE:** `{', '.join(cwe_ids) if isinstance(cwe_ids, list) else cwe_ids}`\n")

            desc = info.get("description", "")
            if desc:
                f.write(f"\n**Açıklama:**\n{desc.strip()}\n")

            # Extract request / response evidence if present
            f.write("\n#### 🔬 Yeniden Üretme & PoC Kanıtı\n")
            f.write("```http\n")
            if fi.get("request"):
                f.write(fi["request"][:1000] + "\n")
            else:
                f.write(f"GET {matched_at} HTTP/1.1\nHost: {urlparse(matched_at).netloc or host}\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n")
            f.write("```\n\n")

            if fi.get("response"):
                f.write("```http\n")
                f.write(fi["response"][:800] + "\n[... truncated ...]\n")
                f.write("```\n\n")

            f.write("---\n\n")

    return out_md


def aggregate_outputs(outdir: str) -> str:
    """Aggregates all findings in outdir into report.md."""
    nuclei_json = os.path.join(outdir, "nuclei.json")
    if not os.path.exists(nuclei_json):
        print(f"[*] {nuclei_json} bulunamadı, boş veya alternatif taranıyor...")

    findings = parse_nuclei_json(nuclei_json)
    ranked = rank_findings(findings)
    report_file = os.path.join(outdir, "report.md")
    generate_markdown_report(ranked, report_file, outdir=outdir)
    print(f"[✓] Triage ve PoC raporu üretildi: {report_file} ({len(ranked)} Nuclei bulgusu)")
    return report_file


def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Reconnaissance & Triage Orchestrator")
    parser.add_argument("--aggregate", help="Aggregate pipeline outputs into Markdown report", action="store_true")
    parser.add_argument("--outdir", help="Outputs directory", default="outputs")
    parser.add_argument("--input", help="Input JSON file with target URLs", default=None)
    parser.add_argument("--out", help="Output path for validation results", default="outputs/validation.json")
    args = parser.parse_args()

    if args.aggregate:
        aggregate_outputs(args.outdir)
        return

    if args.input and os.path.exists(args.input):
        with open(args.input, "r", encoding="utf-8") as f:
            data = json.load(f)
        targets = []
        if isinstance(data, list):
            for d in data:
                if isinstance(d, dict):
                    targets.append(d.get("host") or d.get("url") or "")
                elif isinstance(d, str):
                    targets.append(d)
        asyncio.run(validate_targets(targets, args.out))
        print(f"[✓] Hedefler doğrulandı ve kaydedildi: {args.out}")
        return

    # Default action
    aggregate_outputs(args.outdir)


if __name__ == "__main__":
    main()
