import logging
import dns.resolver

from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration
from certbot.plugins.dns_common import DNSAuthenticator

from rcode0_client import Rcode0Client

logger = logging.getLogger(__name__)

class Authenticator(DNSAuthenticator):
    """DNS Authenticator for RcodeZero DNS"""

    description = 'Obtain certificates using a DNS TXT record (if you are using RcodeZero for DNS).'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._rcode0_client = None

    def _setup_credentials(self):
        self.credentials: CredentialsConfiguration = self._configure_credentials(
            'credentials',
            'Path to RcodeZero DNS API credentials INI file',
            {
                'dns_rcode0_api_key': 'RcodeZero API key to access the DNS API',
            }
        )

    def _perform(self, domain, validation_name, validation):
        record_name = validation_name.rstrip('.')

        # 🧠 CNAME-Auflösung
        resolved = self._resolve_cname(record_name)
        if resolved != record_name:
            logger.info(f"CNAME erkannt für {record_name} → {resolved}")
            record_name = resolved

        self._get_rcode0_client().add_txt_record(record_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        record_name = validation_name.rstrip('.')
        resolved = self._resolve_cname(record_name)
        if resolved != record_name:
            logger.info(f"CNAME erkannt (cleanup) für {record_name} → {resolved}")
            record_name = resolved

        self._get_rcode0_client().del_txt_record(record_name, validation)

    def _resolve_cname(self, name):
        """Löst einen CNAME auf, gibt ansonsten den Originalnamen zurück"""
        try:
            answers = dns.resolver.resolve(name, 'CNAME')
            return str(answers[0].target).rstrip('.')
        except dns.resolver.NoAnswer:
            return name
        except Exception as e:
            logger.warning(f"Fehler bei CNAME-Auflösung für {name}: {e}")
            return name

    def _get_rcode0_client(self):
        if not self._rcode0_client:
            self._rcode0_client = Rcode0Client(api_key=self.credentials.conf['dns_rcode0_api_key'])
        return self._rcode0_client
