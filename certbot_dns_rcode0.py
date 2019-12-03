"""
This module defines a certbot plugin to automate the process of completing a
``dns-01`` challenge (`~acme.challenges.DNS01`) by creating, and subsequently
removing, TXT records using the RcodeZero DNS API.
"""

# Keep metadata before any imports (for setup.py)!
__version__ = '0.0.0.1'
__url__     = 'https://github.com/nic-at/certbot-dns-rcode0'
__all__     = ['Authenticator']

from lexicon.providers import rcodezero
import zope.interface

from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins import dns_common_lexicon

RCODE0_API_URL = 'https://my.rcodezero.at/'


@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator for RcodeZero DNS

    This Authenticator uses the RcodeZero DNS API to fulfill a dns-01 challenge.
    """

    description = ('Obtain certificates using a DNS TXT record  for your'
                   'domains hosted with RcodeZero DNS.')

    def __init__(self, *args, **kwargs):
        super(Authenticator, self).__init__(*args, **kwargs)
        self.credentials = None

    @classmethod
    def add_parser_arguments(cls, add):
        super(Authenticator, cls).add_parser_arguments(add)
        add('credentials', help='rcode0 credentials INI file.')

    def more_info(self):
        return ('This plugin configures a DNS TXT record to respond to a '
                'dns-01 challenge using thei RcodeZero DNS API.')

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'rcodezero credentials INI file',
            {
                'api-key':      'ACME-token for RcodeZero DNS API,'
                                'see https://my.rcodezero.at/api-doc'
            }
        )

    def _perform(self, domain, validation_name, validation):
        self._get_rcode0_client().add_txt_record(
            domain, validation_name, validation)

    def _cleanup(self, domain, validation_name, validation):
        self._get_rcode0_client().del_txt_record(
            domain, validation_name, validation)

    def _get_rcode0_client(self):
        credentials = self.credentials.conf
        return _Rcode0LexiconClient(
            credentials('api-key'))
    

class _Rcode0LexiconClient(dns_common_lexicon.LexiconClient):
    """Encapsulates all communication with the RcodeZeroDNS API via Lexicon."""

    def __init__(self, api_key):
        super(_Rcode0LexiconClient, self).__init__()
        config = dns_common_lexicon.build_lexicon_config('rcode0', {}, {
            'auth_token':       api_key
        })
        self.provider = rcodezero.Provider(config)

    # called while guessing domain name (going from most specific to tld):
    def _handle_http_error(self, e, domain_name):
        if '404 Client Error:' in str(e):
            return None
        return super(_Rcode0LexiconClient, self)._handle_http_error(e, domain_name)

    # called while guessing domain name (going from most specific to tld):
    def _handle_general_error(self, e, domain_name):
        if 'Value in field domainname does not match requirements' in str(e):
            return None
        return super(_Rcode0LexiconClient, self)._handle_general_error(e, domain_name)
