from OpenSSL import crypto
import random


def generate_ca_files():
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, 2048)

    ca = crypto.X509()
    ca.set_pubkey(pkey)

    ca.get_subject().countryName = "US"
    ca.get_subject().stateOrProvinceName = "Somewhere"
    ca.get_subject().localityName = "Somehere"
    ca.get_subject().organizationName = "EvilCorp"
    ca.get_subject().commonName = "benign.company"

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
    csr.get_subject().countryName = "XX"
    csr.get_subject().stateOrProvinceName = "Nowhere"
    csr.get_subject().localityName = "Nowhere"
    csr.get_subject().organizationName = "SneakyCorp"
    csr.get_subject().commonName = "fake.server.io"
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
    cert.set_serial_number(random.randint(10041, 999999999))
    cert.add_extensions(csr.get_extensions())

    cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", False, b"CA:FALSE"),
        crypto.X509Extension(
            b"keyUsage",
            False,
            b"Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment"
        ),
    ])

    cert.add_extensions([
        crypto.X509Extension(b"authorityKeyIdentifier", False, b"keyid:always", issuer=ca_pem)
    ])

    cert.sign(ca_key, "sha256")

    with open("tls/server.pem", "wb") as file:
        file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
