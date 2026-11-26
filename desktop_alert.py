
# PunyGuard XDR
# Windows Desktop Security and Monitoring Alerts

from winotify import Notification


def show_notification(title, message):
    """Display a Windows desktop notification."""
    try:
        alert = Notification(
            app_id="PunyGuard XDR",
            title=title,
            msg=message,
            duration="long"
        )

        alert.show()
        print("[NOTIFICATION] Windows notification sent")
        return True

    except Exception as error:
        print("[ERROR] Windows notification failed:", error)
        return False


def send_security_alert(domain, risk_level, risk_score):
    """Alert when a suspicious domain is detected."""
    title = f"Security Alert - {risk_level}"

    message = (
        f"Suspicious domain: {domain}\n"
        f"Risk Score: {risk_score}/100"
    )

    return show_notification(title, message)


def send_monitoring_alert(message):
    """Alert when PunyGuard monitoring needs attention."""
    return show_notification(
        "PunyGuard XDR - Monitoring Warning",
        message
    )


if __name__ == "__main__":
    print("=" * 60)
    print("PUNYGUARD XDR - NOTIFICATION TEST")
    print("=" * 60)

    send_security_alert(
        domain="xn--mazon-3ve.example",
        risk_level="CRITICAL",
        risk_score=100
    )

    send_monitoring_alert(
        "Test alert: PunyGuard monitoring notification is working."
    )
