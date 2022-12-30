import string
from collections import defaultdict
from typing import Set, Dict

VALID_CHARS = string.ascii_letters + string.digits + ".-_"


def get_unique_dns_queries_from_pcap(pcap: str) -> Set:
    # Defer these imports to this function, as they take time to load!
    from scapy.layers.dns import DNSQR
    from scapy.utils import rdpcap

    dns_queries = set()
    pcap = rdpcap(pcap)
    for packet in pcap:
        if packet.haslayer(DNSQR):
            dns_queries.add(packet[DNSQR].qname.decode())

    return dns_queries


def get_target_dns_queries(baseline_pcap: str, target_pcap: str) -> Dict[str, list]:
    dns = defaultdict(list)

    baseline_dns = get_unique_dns_queries_from_pcap(baseline_pcap)
    target_dns = get_unique_dns_queries_from_pcap(target_pcap)

    dns_queries = target_dns - baseline_dns

    for query in dns_queries:
        if not all(character in VALID_CHARS for character in query):
            continue
        if query[-1] == '.':
            parts = query.split(".")
            tldm = ".".join(parts[-3:])
            dns[tldm].append(query)

    return dns
