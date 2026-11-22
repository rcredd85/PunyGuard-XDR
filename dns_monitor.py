
# PunyGuard XDR
# Live DNS Monitoring Engine

from scapy.all import sniff, DNS, DNSQR, get_if_list
from detector import detect_threat
from datetime import datetime, timezone
from unittest.mock import patch
import time

seen_domains = {}



def monitor_dns(packet):
    if not packet.haslayer(DNS):
        return

    if packet[DNS].qr != 0 or not packet.haslayer(DNSQR):
        return


    try:
        domain = packet[DNSQR].qname.decode(
            "ascii"
        ).rstrip(".").lower()
    except UnicodeDecodeError:
        return

    now = time.monotonic()

    # Avoid analyzing the same domain repeatedly
    if now - seen_domains.get(domain, -5) < 5:
        return

    seen_domains[domain] = now

    print("\n" + "=" * 60)
    print("[LIVE DNS REQUEST]")
    print("Timestamp:", datetime.now(timezone.utc).isoformat())
    print("Requested Domain:", domain)

    # Disable external API calls during initial testing
    with patch(
        "detector.check_domain",
        return_value={"status": "Live API lookup disabled"}
    ):
        detect_threat(domain)

if __name__ == "__main__":
    print("=" * 60)
    print("PUNYGUARD XDR - LIVE DNS MONITOR")
    print("Monitoring authorized DNS traffic")
    print("Press CTRL+C to stop")
    print("=" * 60)

    print("\nAvailable interfaces:")
    for interface in get_if_list():
        print(interface)

    from scapy.all import get_working_ifaces

    wifi = next(
        (
            iface for iface in get_working_ifaces()
            if "Qualcomm QCA61x4A" in iface.description
        ),
        None
    )

    if wifi is None:
        print("[ERROR] Qualcomm Wi-Fi adapter not found")
    else:
        print("\nSelected adapter:", wifi.description)
        print("[ACTIVE] Monitoring DNS requests")
        print("Press CTRL+C to stop")

        sniff(
            iface=wifi,
            filter="udp port 53 or tcp port 53",
            prn=monitor_dns,
            store=False
        )
