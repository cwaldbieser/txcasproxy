
#=======================================================================
# Customized TLS client connections.
#=======================================================================

import urlparse
from OpenSSL import crypto
from twisted.internet import ssl, defer 
from twisted.internet.endpoints import clientFromString
from twisted.internet.interfaces import IOpenSSLClientConnectionCreator
from twisted.python.components import proxyForInterface
from twisted.web.error import SchemeNotSupported
from twisted.web.iweb import IPolicyForHTTPS
from zope.interface import implementer

#----------------------------------------------------------------------
# A custom IPolicyForHTTPS that allows *adding* extra CAs to the OS
# supplied CA bundle.
# Use this as the `contextFactory` for `twisted.web.client.Agent`.
#----------------------------------------------------------------------
class AddExtraTrustRoots(proxyForInterface(IOpenSSLClientConnectionCreator)):
    def __init__(self, extraTrustRoots, original):
        self._extraTrustRoots = extraTrustRoots
        super(AddExtraTrustRoots, self).__init__(original)


    def clientConnectionForTLS(self, tlsProtocol):
        connection = (super(AddExtraTrustRoots, self).clientConnectionForTLS(tlsProtocol))
        cert_store = connection.get_context().get_cert_store()
        for cert in self._extraTrustRoots:
            cert_store.add_cert(cert)
        return connection
 
@implementer(IPolicyForHTTPS)
class CustomPolicyForHTTPS(object):
    """
    SSL connection creator for web clients.
    """
    def __init__(self, extraTrustRoots=None):
        if extraTrustRoots is None:
            extraTrustRoots = []
        self._extraTrustRoots = extraTrustRoots

    def creatorForNetloc(self, hostname, port):
        return AddExtraTrustRoots(
            self._extraTrustRoots, 
            ssl.optionsForClientTLS(hostname.decode("ascii")))

class WebClientEndpointFactory(object):
    """
    An Agent endpoint factory based on endpoint strings.
    """
    def __init__(self, reactor, endpoint_s):
        self.reactor = reactor
        self.endpoint_s = endpoint_s

    def endpointForURI(self, uri):
        p = urlparse.urlparse(uri)
        valid = False
        if p.scheme == 'http' and self.endpoint_s.startswith('tcp:'):
            supported = True
        elif p.scheme == 'https' and self.endpoint_s.startswith('tls:'):
            supported = True
        if not supported:
            raise SchemeNotSupported(
                "Scheme '{0}' is not supported for endpoint '{1}'.".format(
                    p.scheme, self.endpoint_s))
        return clientFromString(self.endpoint_s) 
