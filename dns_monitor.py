
# PunyGuard XDR
# Live DNS Monitoring Engine

from scapy.all import sniff, DNS, DNSQR, get_if_list
from detector import detect_threat
from datetime import datetime, timezone
from unittest.mock import patch
import time

seen_domains = {}

# PunyGuard XDR - Monitoring Heartbeat
import json
from pathlib import Path

STATUS_FILE = Path(__file__).resolve().parent / "logs" / "monitor_status.json"

dns_packet_count = 0
last_dns_request = None


def save_monitor_status():
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)

    status = {
        "monitor": "PunyGuard XDR",
        "status": "running",
        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        "dns_packets_captured": dns_packet_count,
        "last_dns_request": last_dns_request
    }

    temporary_file = STATUS_FILE.with_suffix(".tmp")
    temporary_file.write_text(
        json.dumps(status, indent=4),
        encoding="utf-8"
    )
    temporary_file.replace(STATUS_FILE)


def monitor_dns(packet):

    global dns_packet_count, last_dns_request

    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        dns_packet_count += 1
        last_dns_request = datetime.now(timezone.utc).isoformat()

        if dns_packet_count == 1 or dns_packet_count % 10 == 0:
            save_monitor_status()

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
