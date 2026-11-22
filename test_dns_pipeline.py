
from scapy.all import IP, UDP, DNS, DNSQR
from dns_monitor import monitor_dns

# Simulated DNS request for a test domain
packet = (
    IP(src="192.0.2.10", dst="192.0.2.53")
    / UDP(sport=53000, dport=53)
    / DNS(
        id=1234,
        qr=0,
        qd=DNSQR(qname="xn--mazon-3ve.example")
    )
)

print("Testing PunyGuard XDR DNS pipeline...")
monitor_dns(packet)
print("Test completed.")
