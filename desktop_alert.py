
# PunyGuard XDR - Windows Desktop Security Alerts

from winotify import Notification


def send_security_alert(domain, risk_level, risk_score):
    alert = Notification(
        app_id="PunyGuard XDR",
        title=f"Security Alert - {risk_level}",
        msg=f"Suspicious domain: {domain}\nRisk Score: {risk_score}/100",
        duration="long"
    )

    alert.show()
    print("[NOTIFICATION] Windows security alert sent")


if __name__ == "__main__":
    send_security_alert(
        domain="xn--mazon-3ve.example",
        risk_level="CRITICAL",
        risk_score=100
    )
