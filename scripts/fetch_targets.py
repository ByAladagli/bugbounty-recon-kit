#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bugbounty-recon-kit Target Discovery & Scope Selector:
Queries local datasets (public-bugbounty-programs and bounty-targets-data)
to extract verified, in-scope targets for Bug Bounty programs.
"""
import argparse
import json
import os
import sys
from typing import List, Dict, Any, Optional

try:
    if sys.stdout.encoding != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if sys.stderr.encoding != "utf-8":
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BOUNTY_TARGETS_DIR = r"C:\AI-Tools\repositories\bounty-targets-data\data"
PUBLIC_PROGRAMS_FILE = r"C:\AI-Tools\repositories\public-bugbounty-programs\dist\data.json"


def load_public_programs() -> List[Dict[str, Any]]:
    """Loads programs from projectdiscovery/public-bugbounty-programs."""
    if not os.path.exists(PUBLIC_PROGRAMS_FILE):
        return []
    try:
        with open(PUBLIC_PROGRAMS_FILE, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
            return data.get("programs", [])
    except Exception as e:
        print(f"[!] Error reading public programs: {e}", file=sys.stderr)
        return []


def load_bounty_targets(platform: str = "all") -> List[Dict[str, Any]]:
    """Loads programs from arkadiyt/bounty-targets-data."""
    results = []
    if not os.path.exists(BOUNTY_TARGETS_DIR):
        return results

    files_map = {
        "hackerone": "hackerone_data.json",
        "bugcrowd": "bugcrowd_data.json",
        "intigriti": "intigriti_data.json",
        "yeswehack": "yeswehack_data.json"
    }

    targets_to_load = files_map.items() if platform == "all" else [(platform, files_map.get(platform))]

    for plat_name, fname in targets_to_load:
        if not fname:
            continue
        full_path = os.path.join(BOUNTY_TARGETS_DIR, fname)
        if os.path.exists(full_path):
            try:
                with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                    progs = json.load(f)
                    for p in progs:
                        p["_platform"] = plat_name
                        results.append(p)
            except Exception as e:
                print(f"[!] Error reading {fname}: {e}", file=sys.stderr)
    return results


def search_and_extract_targets(
    query: str = "",
    bounty_only: bool = True,
    platform: str = "all",
    limit: int = 50
) -> Dict[str, Any]:
    """Searches programs matching query and extracts in-scope domain targets."""
    q_low = query.strip().lower()
    matched_programs = []
    in_scope_domains = set()

    # 1. Search public-bugbounty-programs
    pub_progs = load_public_programs()
    for p in pub_progs:
        name = p.get("name", "")
        url = p.get("url", "")
        is_bounty = p.get("bounty", False)

        if bounty_only and not is_bounty:
            continue

        if not q_low or q_low in name.lower() or q_low in url.lower():
            domains = p.get("domains", [])
            for d in domains:
                clean_d = d.strip().lstrip("*.").lower()
                if clean_d and not clean_d.startswith("#") and "." in clean_d:
                    in_scope_domains.add(clean_d)

            matched_programs.append({
                "source": "public-bugbounty-programs",
                "name": name,
                "url": url,
                "bounty": is_bounty,
                "domains_count": len(domains),
                "domains": domains[:15]
            })

    # 2. Search bounty-targets-data
    bounty_progs = load_bounty_targets(platform=platform)
    for p in bounty_progs:
        name = p.get("name", "")
        url = p.get("url", "")
        offers_bounties = p.get("offers_bounties", True)

        if bounty_only and not offers_bounties:
            continue

        if not q_low or q_low in name.lower() or q_low in url.lower():
            # In HackerOne / Bugcrowd format: targets.in_scope
            in_scope = p.get("targets", {}).get("in_scope", [])
            extracted = []
            for t in in_scope:
                asset = t.get("asset_identifier") or t.get("target") or ""
                asset_clean = asset.strip().lstrip("*.").lower()
                if asset_clean and "." in asset_clean and not asset_clean.startswith("http"):
                    in_scope_domains.add(asset_clean)
                    extracted.append(asset_clean)
                elif asset_clean.startswith("http"):
                    from urllib.parse import urlparse
                    parsed = urlparse(asset_clean)
                    if parsed.netloc:
                        in_scope_domains.add(parsed.netloc.lower())
                        extracted.append(parsed.netloc.lower())

            matched_programs.append({
                "source": f"bounty-targets-data ({p.get('_platform')})",
                "name": name,
                "url": url,
                "bounty": offers_bounties,
                "domains_count": len(extracted),
                "domains": extracted[:15]
            })

    sorted_domains = sorted(list(in_scope_domains))
    return {
        "query": query,
        "bounty_only": bounty_only,
        "total_matched_programs": len(matched_programs),
        "total_unique_domains": len(sorted_domains),
        "programs": matched_programs[:limit],
        "in_scope_domains": sorted_domains
    }


def main():
    parser = argparse.ArgumentParser(description="Bug Bounty Program Scope & In-Scope Target Extractor")
    parser.add_argument("-q", "--query", default="", help="Search query (e.g., 'shopify', 'gitlab', 'cloudflare', 'yahoo')")
    parser.add_argument("--bounty-only", action="store_true", default=True, help="Only return paid bug bounty programs (skip unpaid VDP)")
    parser.add_argument("--all-programs", dest="bounty_only", action="store_false", help="Include unpaid VDP programs")
    parser.add_argument("-p", "--platform", default="all", choices=["all", "hackerone", "bugcrowd", "intigriti", "yeswehack"], help="Filter by platform")
    parser.add_argument("-o", "--output", default="targets.txt", help="Output file path for in-scope domains")
    parser.add_argument("--limit", type=int, default=20, help="Max programs to display in stdout")
    args = parser.parse_args()

    print(f"[*] Searching Bug Bounty Programs (Query: '{args.query}', Bounty Only: {args.bounty_only}, Platform: {args.platform})...")
    res = search_and_extract_targets(
        query=args.query,
        bounty_only=args.bounty_only,
        platform=args.platform,
        limit=args.limit
    )

    print(f"[✓] Eşleşen Program Sayısı: {res['total_matched_programs']}")
    print(f"[✓] Toplam Benzersiz In-Scope Hedef Domain: {res['total_unique_domains']}")

    for i, p in enumerate(res["programs"], 1):
        print(f"  {i}. [{p['source']}] {p['name']} (Ödüllü: {p['bounty']}, {p['domains_count']} domain)")
        if p.get("url"):
            print(f"     URL: {p['url']}")

    if res["in_scope_domains"]:
        out_path = os.path.abspath(args.output)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            for d in res["in_scope_domains"]:
                f.write(f"{d}\n")
        print(f"\n[🎯] Hedefler başarıyla kaydedildi: {out_path} ({len(res['in_scope_domains'])} satır)")
        print(f"     Boru hattını başlatmak için: .\\scripts\\recon_pipeline.ps1 -TargetsFile {args.output}")
    else:
        print("[!] Eşleşen in-scope domain bulunamadı. Lütfen sorguyu genişletin.")


if __name__ == "__main__":
    main()
