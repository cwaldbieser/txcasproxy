
# External modules
from characteristic import attributes
from OpenSSL import crypto
from twisted.internet._sslverify import IOpenSSLTrustRoot
from twisted.web.client import BrowserLikePolicyForHTTPS, Agent
from zope.interface import implementer

@implementer(IOpenSSLTrustRoot)
@attributes(["extra_cert_paths"])
class MyCATrustRoot(object):
    def _addCACertsToContext(self, context):
        context.set_default_verify_paths()
        store = context.get_cert_store()
        for path in self.extra_cert_paths:
            with open(path, "rb") as f:
                buffer = f.read()
            certificate = crypto.load_certificate(crypto.FILETYPE_PEM, buffer)
            store.add_cert(certificate)

