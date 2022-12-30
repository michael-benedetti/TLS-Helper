from __future__ import annotations

from pathlib import Path

import click
from click_option_group import optgroup, RequiredMutuallyExclusiveOptionGroup

from tlshelper.domain_utilities import get_domains_from_pcap, get_domains_from_file
from tlshelper.generate_cert_chain import generate_ca_files, generate_csr_files, generate_self_signed_cert
from tlshelper.generate_coredns import generate_coredns_config

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


def print_help_msg_and_exit(command, additional_msg=None):
    with click.Context(command) as ctx:
        if additional_msg:
            click.echo(additional_msg)
            click.echo()
        click.echo(command.get_help(ctx))

    exit(1)


@click.command(no_args_is_help=True, context_settings=CONTEXT_SETTINGS)
@optgroup.group("Domain Extraction", cls=RequiredMutuallyExclusiveOptionGroup)
@optgroup.option("--file", "-f", type=click.Path(exists=True), help="Path to a file containing domain entries - one per line.")
@optgroup.option("--pcap", "-p", type=click.Path(exists=True), help="Extract DNS queries from a single PCAP.")
@optgroup.option("--pcap-diff", "-d", is_flag=True, help="Perform a diff of two PCAP files - a baseline and a target PCAP.  Produces domains that only exist in the target PCAP and do not exist in the baseline PCAP.")
@optgroup.group("PCAP Diff Options")
@optgroup.option("--baseline-pcap", "-b", type=click.Path(exists=True), help="Path to the baseline PCAP when performing PCAP diff.")
@optgroup.option("--target-pcap", "-t", type=click.Path(exists=True), help="Path to the target PCAP when performing PCAP diff.")
@optgroup.group("Coredns Generation")
@optgroup.option("--coredns", "-c", is_flag=True, help="Generate Coredns config.  Requires an IP address - see --ip-address.")
@optgroup.option("--ip-address", "-i", help="IP address to route traffic to when generating Coredns config files.")
def main(file, pcap, pcap_diff, baseline_pcap, target_pcap, coredns, ip_address):
    """
    Generate a full TLS certificate chain and Coredns configuration without the headache!
    """

    if (pcap or file) and (baseline_pcap or target_pcap):
        print_help_msg_and_exit(main, "Options --baseline-pcap and --target-pcap are only used when performing --pcap-diff!")

    if pcap_diff and (baseline_pcap is None or target_pcap is None):
        print_help_msg_and_exit(main, "Option --pcap-diff requires both a baseline PCAP and target PCAP!")

    if coredns and ip_address is None:
        print_help_msg_and_exit(main, "Option --coredns requires an IP address!")

    if pcap or pcap_diff:
        dns = get_domains_from_pcap(baseline_pcap, target_pcap if target_pcap else pcap)
    else:
        dns = get_domains_from_file(file)

    if coredns:
        Path("coredns").mkdir(exist_ok=True)
        generate_coredns_config(dns, ip_address)

    Path("tls").mkdir(exist_ok=True)

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
