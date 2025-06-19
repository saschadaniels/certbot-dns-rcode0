# encoding: utf-8
from setuptools import setup


def exec_file(path):
    """Execute a python file and return the `globals` dictionary."""
    with open(path, 'rb') as f:
        code = compile(f.read(), path, 'exec')
    namespace = {}
    try:
        exec(code, namespace, namespace)
    except ImportError:     # ignore missing dependencies at setup time
        pass                # and return dunder-globals anyway!
    return namespace


metadata = exec_file('certbot_dns_rcode0.py')

setup(
    version = "1.0.0",
    url     = "https://github.com/saschadaniels/certbot-dns-rcode0",
)
