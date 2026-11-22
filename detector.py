
# PunyGuard XDR
# Phase 4: Automated Threat Intelligence

import idna
from confusable_homoglyphs import confusables
from urllib.parse import urlsplit
from datetime import datetime, timezone
from brand_detector import detect_brand
from threat_intel import check_domain
from security_logger import log_security_event
from desktop_alert import send_security_alert


def detect_threat(url):
    try:
        target = url if "://" in url else "//" + url
        domain = urlsplit(target).hostname

        if not domain:
            print("[ERROR] Invalid domain")
            return

        ascii_domain = idna.encode(domain, uts46=True).decode("ascii")
        unicode_domain = idna.decode(ascii_domain)

        punycode = any(
            label.startswith("xn--")
            for label in ascii_domain.split(".")
        )

        mixed_script = any(
            confusables.is_mixed_script(label)
            for label in unicode_domain.split(".")
        )

     
        homoglyph = (
            not unicode_domain.isascii()
            and bool(
                confusables.is_confusable(
                    unicode_domain,
                    preferred_aliases=["latin"]
                )
            )
        )


        brand = detect_brand(unicode_domain)

        risk_score = 0
        findings = []

        if punycode:
            risk_score += 20
            findings.append("Punycode detected")

        if mixed_script:
            risk_score += 30
            findings.append("Mixed Unicode scripts detected")

        if homoglyph:
            risk_score += 40
            findings.append("Potential deceptive characters")

        if brand:
            risk_score += 50
            findings.append(
                f"Potential brand impersonation: {brand.upper()}"
            )

        risk_score = min(risk_score, 100)

        if risk_score >= 70:
            risk = "CRITICAL"
        elif risk_score >= 50:
            risk = "HIGH"
        elif risk_score >= 30:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        print("\nTimestamp:", datetime.now(timezone.utc).isoformat())
        print("Domain:", ascii_domain)
        print("Decoded Domain:", unicode_domain)
        print("Risk Score:", f"{risk_score}/100")
        print("Risk Level:", risk)
        print("Targeted Brand:", brand.upper() if brand else "None detected")

        for finding in findings:
            print("[DETECTION]", finding)
       
        

        # Log and notify on high-risk detections
        if risk_score >= 50:
            print("[ALERT] SOC investigation required")

            log_security_event(
                domain=ascii_domain,
                risk_score=risk_score,
                risk_level=risk,
                targeted_brand=brand,
                findings=findings
            )

            try:
                send_security_alert(
                    domain=ascii_domain,
                    risk_level=risk,
                    risk_score=risk_score
                )
            except Exception as error:
                print("[WARNING] Desktop notification failed:", error)

        # Threat intelligence lookup
        print("\n[THREAT INTELLIGENCE]")
        intelligence = check_domain(ascii_domain)

        for key, value in intelligence.items():
            print(f"{key}: {value}")

    except (ValueError, UnicodeError) as error:
        print("[ERROR]", error)


if __name__ == "__main__":
    print("=" * 60)
    print("PUNYGUARD XDR - AUTOMATED THREAT INTELLIGENCE")
    print("=" * 60)

    test_domains = [
        "google.com",
        "microsoft.com",
        "apple.com",
        "bücher.example",
        "аpple.example",
        "gооgle.example",
        "microsоft.example",
        "pаypal.example",
        "аmazon.example"
    ]

    for domain in test_domains:
        detect_threat(domain)
        print("-" * 60)
        