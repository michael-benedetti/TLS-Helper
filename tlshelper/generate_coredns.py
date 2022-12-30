from typing import Dict

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
