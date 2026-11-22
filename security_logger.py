
# PunyGuard XDR - Security Event Logger
# Saves structured security events as JSON Lines

import json
from datetime import datetime, timezone
from pathlib import Path

LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_FILE = LOG_DIR / "security_events.jsonl"


def log_security_event(domain, risk_score, risk_level,
                       findings, targeted_brand=None):
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "domain_threat_detection",
        "source": "PunyGuard-XDR",
        "domain": domain,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "targeted_brand": targeted_brand,
        "findings": findings
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event, ensure_ascii=False) + "\n")

    print("[LOGGED] Security event saved")
    return event


if __name__ == "__main__":
    log_security_event(
        domain="xn--mazon-3ve.example",
        risk_score=100,
        risk_level="CRITICAL",
        targeted_brand="AMAZON",
        findings=[
            "Punycode detected",
            "Mixed Unicode scripts detected",
            "Potential brand impersonation"
        ]
    )
