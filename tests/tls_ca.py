"""Throwaway certificate authority and server certificate for the tests."""
from pathlib import Path
import socket
import subprocess


def run(*args: str) -> None:
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def create_certificates(root: Path, san: str) -> tuple[Path, Path, Path, Path]:
    ca = root / "ca.pem"
    key = root / "ca.key"
    server_key = root / "server.key"
    server_csr = root / "server.csr"
    server_cert = root / "server.pem"
    extensions = root / "server.ext"
    extensions.write_text("basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n"
                          f"extendedKeyUsage=serverAuth\nsubjectAltName={san}\n")
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-days", "2", "-subj", "/CN=Fortis TLS test CA", "-addext",
        "basicConstraints=critical,CA:TRUE", "-addext",
        "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(key), "-out", str(ca))
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-sha256",
        "-subj", "/CN=localhost", "-keyout", str(server_key), "-out", str(server_csr))
    run("openssl", "x509", "-req", "-in", str(server_csr), "-CA", str(ca),
        "-CAkey", str(key), "-CAcreateserial", "-days", "2", "-sha256",
        "-extfile", str(extensions), "-out", str(server_cert))
    other_ca = root / "other-ca.pem"
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-days", "2", "-subj", "/CN=Untrusted test CA", "-keyout",
        str(root / "other-ca.key"), "-out", str(other_ca))
    return ca, server_cert, server_key, other_ca
