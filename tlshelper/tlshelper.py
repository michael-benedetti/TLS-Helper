from __future__ import annotations

from pathlib import Path

import click

from tlshelper.dns_utilities import get_target_dns_queries
from tlshelper.generate_cert_chain import generate_ca_files, generate_csr_files, generate_self_signed_cert
from tlshelper.generate_coredns import generate_coredns_config

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.command(no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
@click.argument("ip_address")
@click.argument("baseline_pcap", type=click.Path(exists=True))
@click.argument("target_pcap", type=click.Path(exists=True))
def main(ip_address, baseline_pcap, target_pcap):
    """
    Provided an IP, baseline PCAP, and target PCAP, TLS Helper will diff the two PCAPs and produce Coredns configs and
    a full TLS certificate chain including root CA certificate for DNS entries that exist in the target PCAP that do
    not exist in the baseline PCAP.

    \b
    IP_ADDRESS: An IP address that is accessible by your target
    BASELINE_PCAP: A pcap that was collected before target activity has occurred
    TARGET_PCAP: A pcap that was collected after target activity has occurred
    """

    Path("coredns").mkdir(exist_ok=True)
    Path("tls").mkdir(exist_ok=True)

    dns = get_target_dns_queries(baseline_pcap, target_pcap)

    generate_coredns_config(dns, ip_address)
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
