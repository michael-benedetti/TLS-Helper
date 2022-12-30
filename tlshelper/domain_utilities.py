import string
from collections import defaultdict
from typing import Set, Dict

VALID_CHARS = string.ascii_letters + string.digits + ".-_"


def unique_domains_to_dict(domains: Set[str]) -> Dict[str, list]:
    result = defaultdict(list)

    for domain in domains:
        if not all(character in VALID_CHARS for character in domain):
            continue
        if domain[-1] == '.':
            parts = domain.split(".")
            tldm = ".".join(parts[-3:])
            result[tldm].append(domain)

    return result


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


def get_domains_from_pcap(baseline_pcap: str, target_pcap: str) -> Dict[str, list]:
    target_dns = get_unique_dns_queries_from_pcap(target_pcap)

    if baseline_pcap is None:
        baseline_dns = set()
    else:
        baseline_dns = get_unique_dns_queries_from_pcap(baseline_pcap)

    dns_queries = target_dns - baseline_dns

    return unique_domains_to_dict(dns_queries)


def get_domains_from_file(file: str) -> Dict[str, list]:
    with open(file, "r") as f:
        domains = set(f.readlines())

    domains = set(domain.strip() + "." for domain in domains if domain.strip()[-1] != ".")

    return unique_domains_to_dict(domains)
