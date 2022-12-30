from __future__ import annotations

import string

import sys
from pathlib import Path
from typing import Set, Dict

from OpenSSL import crypto

COREDNS_TEMPLATE = """\
$ORIGIN [TOPLEVEL]
@   3600 IN SOA sns.dns.icann.org. noc.dns.icann.org. (
                2017042745 ; serial
                7200    ; refresh (2 hours)
                3600    ; retry (1 hour)
                1209600 ; expire (2 weeks)
                3600    ; minimum (1 hour)
                )

        3600 IN NS a.iana-servers.net.
        3600 IN NS b.iana-servers.net.

[ENTRIES]
"""

VALID_CHARS = string.ascii_letters + string.digits + ".-_"


def get_unique_dns_queries_from_pcap(pcap: str) -> Set:
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


def generate_coredns_config(dns: Dict[str, list], ip: str) -> None:
    for tldm, entries in dns.items():
        formatted_entries = []
        entries = sorted(entries, key=len)
        for entry in entries:
            formatted_entries.append(f"{'.'.join(entry.split('.')[0:-3])}\tIN A\t{ip}\n\t\tIN AAAA ::1")

        domain_config = COREDNS_TEMPLATE
        domain_config = domain_config.replace("[TOPLEVEL]", tldm)
        domain_config = domain_config.replace("[ENTRIES]", "\n".join(formatted_entries))

        with open(f"coredns/db.{tldm}txt", "w") as file:
            file.write(domain_config)

    with open("coredns/Corefile", "w") as file:
        for tldm in dns:
            file.write(f"{tldm[0:-1]}" + " {" + f"\n  file /coreconfig/db.{tldm}txt\n  log\n" + "}\n")


def generate_ca_files():
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)

    ca = crypto.X509()
    ca.set_pubkey(pkey)

    ca.get_subject().C = "US"
    ca.get_subject().ST = "Somewhere"
    ca.get_subject().L = "Somehere"
    ca.get_subject().O = "EvilCorp"
    ca.get_subject().CN = "benign.company"

    ca.set_issuer(ca.get_subject())

    ca.gmtime_adj_notBefore(0)
    ca.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)

    ca.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
        crypto.X509Extension(b"keyUsage", False, b"keyCertSign, cRLSign"),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca),
    ])

    ca.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca)
    ])

    ca.sign(pkey, "sha256")

    pem = crypto.dump_certificate(crypto.FILETYPE_PEM, ca)
    key = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)

    with open("tls/CA.key", "wb") as file:
        file.write(key)

    with open("tls/CA.pem", "wb") as file:
        file.write(pem)


def generate_csr_files(dns):
    alt_names = []
    i = 1
    for tldm in dns:
        alt_names.append(f"DNS.{i}:{tldm[:-1]}".encode())
        alt_names.append(f"DNS.{i + 1}:*.{tldm[:-1]}".encode())
        i += 2

    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)

    csr = crypto.X509Req()
    csr.set_pubkey(pkey)
    csr.get_subject().C = "XX"
    csr.get_subject().ST = "Nowhere"
    csr.get_subject().L = "Nowhere"
    csr.get_subject().O = "SneakyCorp"
    csr.get_subject().CN = "fake.server.io"
    csr.add_extensions([
        crypto.X509Extension(b"subjectAltName", False, b", ".join(alt_names))
    ])

    csr.sign(pkey, "sha256")

    pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    server_key = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)

    with open("tls/server.key", "wb") as file:
        file.write(server_key)

    with open("tls/server.csr", "wb") as file:
        file.write(pem)


def generate_self_signed_cert():
    with open("tls/CA.pem", "rb") as file:
        ca_pem = crypto.load_certificate(crypto.FILETYPE_PEM, file.read())
    with open("tls/CA.key", "rb") as file:
        ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, file.read())
    with open("tls/server.csr", "rb") as file:
        csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, file.read())

    cert = crypto.X509()
    cert.set_pubkey(csr.get_pubkey())
    cert.set_subject(csr.get_subject())
    cert.set_issuer(ca_pem.get_subject())
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    cert.set_serial_number(random.randint(10041,999999999))
    cert.add_extensions(csr.get_extensions())

    cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        crypto.X509Extension(b"keyUsage", False, b"Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment"),
    ])

    cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_pem)
    ])

    cert.sign(ca_key, "sha256")

    with open("tls/server.pem", "wb") as file:
        file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print()
        print(f"Usage: {sys.argv[0]} IP_ADDRESS BASELINE_PCAP TARGET_PCAP\n")
        print(f"    IP_ADDRESS: An IP address that is accessible by your target\n"
              f"    BASELINE_PCAP: A pcap that was collected before target activity has occurred\n"
              f"    TARGET_PCAP: A pcap that was collected after target activity has occurred\n")
        exit()

    from scapy.all import *
    from scapy.layers.dns import DNSQR

    Path("coredns").mkdir(exist_ok=True)
    Path("tls").mkdir(exist_ok=True)

    ip = sys.argv[1]
    baseline_pcap = sys.argv[2]
    target_pcap = sys.argv[3]

    dns = get_target_dns_queries(baseline_pcap, target_pcap)

    generate_coredns_config(dns, ip)
    generate_ca_files()
    generate_csr_files(dns)
    generate_self_signed_cert()

    print()
    print("[+] Finished parsing DNS logs!")
    print("[!] Coredns config files are located in ./coredns")
    print("[!] SSL CA, CSR, and server certs are located in ./tls")
    print("[!]     1.) Create a web server that uses server.key and server.pem")
    print("[!]     2.) Load CA.pem as a trusted cert on your target device")
