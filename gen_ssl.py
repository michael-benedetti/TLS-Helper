from __future__ import annotations

import string
from subprocess import Popen, PIPE

import sys
from pathlib import Path
from typing import Set, Dict

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

SAN_CNF_TEMPLATE = """\
[req]
default_bits            = 2048
distinguished_name      = req_distinguished_name
req_extensions          = req_ext

[req_distinguished_name]
countryName             = Country Name (2 letter code)
stateOrProvinceName     = State or Province Name (full name)
localityName            = Locality Name (eg, city)
organizationName        = Organization Name (eg, company)
commonName              = Common Name (e.g. server FQDN or YOUR name)

[req_ext]
subjectAltName          = @alt_names

[alt_names]
[ALT_NAMES_HERE]
"""

WEBCERT_EXT_TEMPLATE = """\
authorityKeyIdentifier = keyid,issuer
basicConstraints = CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[ alt_names ]
[ALT_NAMES_HERE]
"""

VALID_CHARS = string.ascii_letters + string.digits + ".-_"


def run_shell_command(cmd: str) -> tuple[int, str]:
    """
    Run a shell command and return the utf-8 output
    :param cmd: shell command to run as a list
    :return: command output in utf-8
    """
    with Popen(cmd, stdout=PIPE, stderr=PIPE, shell=True) as proc:
        output = proc.communicate()[0].decode()
        return proc.returncode, output


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
    Path("coredns").mkdir(exist_ok=True)
    for tldm, entries in dns.items():
        formatted_entries = []
        for entry in entries:
            formatted_entries.append(f"{'.'.join(entry.split('.')[0:-3])}\tIN A\t{ip}\n\t\tIN AAAA ::1")

        t = COREDNS_TEMPLATE
        t = t.replace("[TOPLEVEL]", tldm)
        t = t.replace("[ENTRIES]", "\n".join(formatted_entries))

        with open(f"coredns/db.{tldm}txt", "w") as file:
            file.write(t)

        with open("coredns/Corefile", "w") as file:
            for tldm in dns: \
            file.write(f"{tldm[0:-1]}" + " {" + f"\n  file /root/db.{tldm}txt\n  log\n" + "}\n")


def generate_openssl_configs(dns: Dict[str, list]):
    Path("ssl").mkdir(exist_ok=True)

    alt_names = []
    i = 1
    for tldm in dns:
        alt_names.append(f"DNS.{i} = {tldm[:-1]}")
        alt_names.append(f"DNS.{i + 1} = *.{tldm[:-1]}")
        i += 2

    with open("ssl/san.cnf", "w") as file:
        file.write(SAN_CNF_TEMPLATE.replace("[ALT_NAMES_HERE]", "\n".join(alt_names)))
    with open("ssl/webcert.ext", "w") as file:
        file.write(WEBCERT_EXT_TEMPLATE.replace("[ALT_NAMES_HERE]", "\n".join(alt_names)))


def generate_ca_files():
    rc, result = run_shell_command('openssl req -subj "/C=CN/ST=Somewhere/L=Somewhere/O=EvilCorp/CN=evil.ca" -x509 -new -newkey rsa:2048 -nodes -keyout ssl/CA.key -sha256 -days 300 -out ssl/CA.pem')
    if rc != 0:
        print("Failed to generate CA.pem")
        exit()


def generate_csr_files():
    rc, result = run_shell_command('openssl req -subj "/C=XX/ST=Nowhere/L=Nowhere/O=SneakyCorp/CN=fake.server.com" -new -newkey rsa:2048 -nodes -keyout ssl/server.key -out ssl/server.csr -config ssl/san.cnf')
    if rc != 0:
        print("Failed to generate server.csr")
        exit()


def generate_self_signed_cert():
    rc, result = run_shell_command("openssl x509 -req -in ssl/server.csr -CA ssl/CA.pem -CAkey ssl/CA.key -CAcreateserial -out ssl/server.pem -days 180 -sha256 -extfile ssl/webcert.ext")
    if rc != 0:
        print(rc, result)
        print("Failed to generate server.pem")
        exit()


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

    ip = sys.argv[1]
    baseline_pcap = sys.argv[2]
    target_pcap = sys.argv[3]

    dns = get_target_dns_queries(baseline_pcap, target_pcap)

    generate_coredns_config(dns, ip)
    generate_openssl_configs(dns)
    generate_ca_files()
    generate_csr_files()
    generate_self_signed_cert()

    print()
    print("[+] Finished parsing DNS logs!")
    print("[!] Coredns config files are located in ./coredns")
    print("[!] SSL CA, CSR, and server certs are located in ./ssl")
    print("[!]     1.) Create a web server that uses server.key andserver.pem")
    print("[!]     2.) Load CA.pem as a trusted cert on your target device")