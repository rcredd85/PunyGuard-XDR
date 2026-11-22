
# PunyGuard XDR
# Automated VirusTotal Threat Intelligence

import os
import requests
from dotenv import load_dotenv
from pathlib import Path

load_dotenv(Path(__file__).parent / ".env")

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def check_domain(domain):

    if not API_KEY:
        return {"error": "API key not configured"}

    if domain.rstrip(".").endswith(".example"):
        return {"status": "Simulated domain - lookup skipped"}

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"

    headers = {
        "x-apikey": API_KEY
    }

    try:
        response = requests.get(
            url, headers=headers, timeout=15
        )

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            return {
                "domain": domain,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0)
            }

        elif response.status_code == 404:
            return {"status": "Domain not found"}

        elif response.status_code == 429:
            return {"status": "API rate limit reached"}

        else:
            return {"error": f"HTTP {response.status_code}"}

    except requests.RequestException:
        return {"error": "VirusTotal connection failed"}


if __name__ == "__main__":
    print("PUNYGUARD XDR - THREAT INTELLIGENCE TEST")

    result = check_domain("google.com")

    for key, value in result.items():
        print(f"{key}: {value}")
