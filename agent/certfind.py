#!/usr/bin/python3
"""Пошук сертифіката для домену (для встановлювача): Let's Encrypt і ssl_certificate з конфігів nginx.

  python3 certfind.py ДОМЕН            → «cert_path key_path trusted» найкращого сертифіката або порожньо
  python3 certfind.py --fp CERT        → SHA-256 відбиток сертифіката (для закріплення в Home Assistant)
Підходить сертифікат, що покриває домен (точно або *.домен), дійсний ще ≥ 7 днів; перевага — довіреним
(Let's Encrypt тощо), далі — з найдовшим терміном.
"""

import datetime as dt
import glob
import hashlib
import os
import re
import subprocess
import sys

from cryptography import x509


def covers(name, host):
    name, host = name.lower(), host.lower()
    if name == host:
        return True
    return name.startswith("*.") and host.count(".") >= 2 and host.split(".", 1)[1] == name[2:]


def pairs():
    out = []
    for d in glob.glob("/etc/letsencrypt/live/*/"):
        out.append((d + "fullchain.pem", d + "privkey.pem"))
    files = [f for pat in ("/etc/nginx/nginx.conf", "/etc/nginx/conf.d/*.conf", "/etc/nginx/sites-enabled/*")
             for f in glob.glob(pat) if os.path.isfile(f)]
    for f in files:
        try:
            text = re.sub(r"#[^\n]*", "", open(f, errors="replace").read())
        except OSError:
            continue
        certs = re.findall(r"\bssl_certificate\s+([^;\s]+)\s*;", text)
        keys = re.findall(r"\bssl_certificate_key\s+([^;\s]+)\s*;", text)
        out += list(zip(certs, keys))
    seen, res = set(), []
    for c, k in out:
        rc = os.path.realpath(c)
        if rc not in seen and os.path.isfile(c) and os.path.isfile(k):
            seen.add(rc)
            res.append((c, k))
    return res


def trusted(cert):
    chain = cert  # fullchain містить проміжні сертифікати
    r = subprocess.run(["openssl", "verify", "-CAfile", "/etc/ssl/certs/ca-certificates.crt", "-untrusted", chain, cert],
                       capture_output=True, text=True)
    return r.returncode == 0


def find(host):
    best = None
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)  # not_valid_after — без часового поясу (UTC)
    for c, k in pairs():
        try:
            cert = x509.load_pem_x509_certificate(open(c, "rb").read())
        except Exception:  # noqa: BLE001
            continue
        try:
            names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            names = []
        if not any(covers(n, host) for n in names):
            continue
        days = (cert.not_valid_after - now).days
        if days < 7:
            continue
        cand = (trusted(c), days, c, k)
        if best is None or cand[:2] > best[:2]:
            best = cand
    return best


def fp(path):
    import ssl
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(path).read().split("-----END CERTIFICATE-----")[0] + "-----END CERTIFICATE-----\n")).hexdigest()


if __name__ == "__main__":
    if sys.argv[1] == "--fp":
        print(fp(sys.argv[2]))
    else:
        b = find(sys.argv[1])
        if b:
            print(b[2], b[3], "trusted" if b[0] else "untrusted")
