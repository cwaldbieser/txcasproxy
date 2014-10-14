#! /usr/bin/env python

# Standard library
import argparse
import sys
import urlparse

# External modules
from OpenSSL import SSL, crypto
from twisted.internet import ssl, task, defer 
from twisted.python.modules import getModule
from twisted.web.client import getPage

import treq
from zope.interface import implementer
from characteristic import attributes
from twisted.internet._sslverify import IOpenSSLTrustRoot
from twisted.web.client import BrowserLikePolicyForHTTPS, Agent
from twisted.web.iweb import IPolicyForHTTPS

#@implementer(IOpenSSLTrustRoot)
#@attributes(["root_certificate_path"])
#class MyCATrustRoot(object):
#    def _addCACertsToContext(self, context):
#        #context.load_verify_locations(self.root_certificate_path)
#        context.set_default_verify_paths()
#        with open(self.root_certificate_path, "rb") as f:
#            buffer = f.read()
#        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, buffer)
#        store = context.get_cert_store()
#        store.add_cert(certificate)
 
from twisted.internet.interfaces import IOpenSSLClientConnectionCreator
from twisted.python.components import proxyForInterface

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
        """
        """
        return AddExtraTrustRoots(
            self._extraTrustRoots, 
            ssl.optionsForClientTLS(hostname.decode("ascii")))

@defer.inlineCallbacks
def main(reactor, args):
    kwds = {}
    
    #client_cert = args.client_cert
    #if client_cert is not None:
    #    clientData = args.client_cert.read()
    #    clientCertificate = ssl.PrivateCertificate.loadPEM(clientData)
    #    kwds['clientCertificate'] = clientCertificate 
    #authority = ssl.Certificate.loadPEM(caCertData)

    host = args.host
    port = args.port
    netloc = "%s:%d" % (host, port)
    
    #extra_cert_opts = {}
    #if args.ssl_method:
    #    m = getattr(SSL, '%s_METHOD' % args.ssl_method)
    #    extra_cert_opts['method'] = m
    #    kwds['extraCertificateOptions'] = extra_cert_opts 
    #options = ssl.optionsForClientTLS( unicode(host), authority, **kwds)
    #s = yield getPage("https://%s/login" % netloc, contextFactory=options)
    #print s
    
    ca_certs = args.ca_cert
    if ca_certs is None:
        ca_certs = []
    extra_ca_certs = []
    for ca_cert in ca_certs:
        with open(ca_cert, "rb") as f:
            data = f.read()
        cert = crypto.load_certificate(crypto.FILETYPE_PEM, data)
        extra_ca_certs.append(cert)
    
    url = urlparse.urljoin("https://%s" % netloc, args.resource)
    #agent = Agent(reactor, contextFactory=BrowserLikePolicyForHTTPS(MyCATrustRoot(root_certificate_path=args.ca_cert)))
    agent = Agent(reactor, contextFactory=CustomPolicyForHTTPS(extra_ca_certs))
    resp = yield treq.get(url, agent=agent)
    content = yield treq.content(resp)
    print content

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="SSL Test Client")

    parser.add_argument(
        '--ca-cert',
        action='store',
        nargs='+',
        help='Use PEM formatted CA_CERT when checking *server* certificate signature.')
    parser.add_argument(
        '--client-cert',
        action='store',
        type=argparse.FileType('rb'),
        help='Use PEM formatted client certificate+private key.  Cert will be presented to server during SSL handshake.')
    parser.add_argument(
        '--host',
        action='store',
        default='localhost',
        help='Connect to HOST')
    parser.add_argument(
        '--port',
        action='store',
        type=int,
        default=443,
        help='Connect to PORT')
    parser.add_argument(
        '--resource',
        action='store',
        default='/login',
        help='Request RESOURCE.')
    #parser.add_argument(
    #    '--ssl-method',
    #    action='store',
    #    choices=['SSLv23', 'SSLv3', 'TLSv1', 'TLSv1_1', 'TLSv1_2'],
    #    help='SSL method.')

    args = parser.parse_args()

    task.react(main, [args])

