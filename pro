from scapy.all import rdpcap, DNS, IP, ICMP, TCP, ARP
from collections import Counter, defaultdict
import csv
from getmac import get_mac_address

# Load the PCAP file
packets = rdpcap("project.pcap")

# Constants for thresholds
THRESHOLDS = {
    "ddos": 100,         # Rule 2: DDoS traffic threshold
    "mtu": 1500,         # Rule 3: Maximum Transmission Unit (MTU)
    "syn_flood": 100,    # Rule 7: SYN flood threshold
    "port_scan": 5,      # Rule 8: Port scan threshold
    "icmp_requests": 10  # Rule 6: ICMP Echo requests threshold
}

# Data structures to track rule-specific anomalies
traffic_count = Counter()          # IP traffic for DDoS detection
syn_packets = defaultdict(int)     # SYN packets per source IP
port_scans = defaultdict(set)      # Ports targeted by each source IP
unsolicited_arps = []              # ARP replies without requests
large_dns_responses = []           # Large DNS response packets
icmp_request_count = Counter()     # ICMP Echo request counts
non_standard_ports = set()         # Non-standard destination ports
packet_sizes = defaultdict(int)    # Track packet sizes for IPs
ip_rule_violations = defaultdict(lambda: [0] * 8)  # Rule violation flags for each IP

# Function to compute MDP
def calculate_mdp(violations):
    return (sum(violations) * 100) / len(violations)

# Analyze packets
for packet in packets:
    if packet.haslayer(IP):
        src_ip = packet[IP].src

        # Rule 1: Non-standard destination ports
        if packet.haslayer(TCP):
            dport = packet[TCP].dport
            if dport not in [80, 443, 22]:  # Exclude common ports
                non_standard_ports.add(dport)

        # Rule 2: High traffic volume (DDoS)
        traffic_count[src_ip] += 1

        # Rule 3: Excessive packet size
        packet_size = len(packet)
        if packet_size > THRESHOLDS["mtu"]:
            packet_sizes[src_ip] = packet_size

        # Rule 4: Unsolicited ARP replies
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP reply
            unsolicited_arps.append(packet)

        # Rule 5: Unusually large DNS responses
        if packet.haslayer(DNS) and packet[DNS].ancount > 0:
            response_size = len(packet[DNS])
            if response_size > 512:  # Standard DNS response limit
                large_dns_responses.append((src_ip, response_size))

        # Rule 6: Excessive ICMP Echo requests
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:  # Echo request
            icmp_request_count[src_ip] += 1

        # Rule 7: SYN flood detection
        if packet.haslayer(TCP) and packet[TCP].flags == 0x02:  # SYN flag
            syn_packets[src_ip] += 1

        # Rule 8: Port scanning
        if packet.haslayer(TCP):
            port_scans[src_ip].add(packet[TCP].dport)

# Assign rule violations for each IP
for ip, count in traffic_count.items():
    ip_rule_violations[ip][1] = 1 if count > THRESHOLDS["ddos"] else 0

for ip, size in packet_sizes.items():
    ip_rule_violations[ip][2] = 1 if size > THRESHOLDS["mtu"] else 0

for arp in unsolicited_arps:
    ip_rule_violations[arp.psrc][3] = 1

for ip, _ in large_dns_responses:
    ip_rule_violations[ip][4] = 1

for ip, count in icmp_request_count.items():
    ip_rule_violations[ip][5] = 1 if count > THRESHOLDS["icmp_requests"] else 0

for ip, count in syn_packets.items():
    ip_rule_violations[ip][6] = 1 if count > THRESHOLDS["syn_flood"] else 0

for ip, ports in port_scans.items():
    ip_rule_violations[ip][7] = 1 if len(ports) > THRESHOLDS["port_scan"] else 0

# Generate the CSV report
with open("report.csv", "w", newline="") as csvfile:
    fieldnames = [
        "IP Address", "MAC Address", "Rule 1", "Rule 2", "Rule 3", "Rule 4",
        "Rule 5", "Rule 6", "Rule 7", "Rule 8", "MDP (%)"
    ]
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for ip, violations in ip_rule_violations.items():
        mac_address = get_mac_address(ip=ip) or "Unknown"
        mdp = calculate_mdp(violations)
        writer.writerow({
            "IP Address": ip,
            "MAC Address": mac_address,
            "Rule 1": 1 if ip in non_standard_ports else 0,
            **{f"Rule {i + 2}": violations[i] for i in range(8)},
            "MDP (%)": mdp
        })

print("Analysis complete. Report saved as 'report.csv'.")
