from __future__ import annotations

import sys
from pathlib import Path

from tlshelper.dns_utilities import get_target_dns_queries
from tlshelper.generate_cert_chain import generate_ca_files, generate_csr_files, generate_self_signed_cert
from tlshelper.generate_coredns import generate_coredns_config


def main():
    if len(sys.argv) < 4:
        print()
        print(f"Usage: {sys.argv[0]} IP_ADDRESS BASELINE_PCAP TARGET_PCAP\n")
        print(f"    IP_ADDRESS: An IP address that is accessible by your target\n"
              f"    BASELINE_PCAP: A pcap that was collected before target activity has occurred\n"
              f"    TARGET_PCAP: A pcap that was collected after target activity has occurred\n")
        exit()

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


if __name__ == '__main__':
    main()
