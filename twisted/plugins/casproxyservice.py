
# Standard library
import sys

# Application modules
from txcasproxy.service import ProxyService

# External modules
from twisted.application.service import IServiceMaker
from twisted.plugin import IPlugin
from twisted.python import usage
from zope.interface import implements


class Options(usage.Options):
    #optFlags = [
    #        ["flag", "f", "A flag."],
    #    ]

    optParameters = [
                        ["endpoint", "e", None, "An endpoint connection string."],
                        ["proxied-url", "p", None, "The base URL to proxy."],
                        ["cas-login", "c", None, "The CAS /login URL."],
                        ["cas-service-validate", "s", None, "The CAS /serviceValidate URL."],
                        ["fqdn", None, None, "Explicitly specify the FQDN that should be included in URL callbacks."],
                    ]

    def __init__(self):
        usage.Options.__init__(self)
        self['authorities'] = []

    def opt_addCA(self, pem_path):
        """
        Add a trusted CA public cert (PEM format).
        """
        self['authorities'].append(pem_path)

    def postOptions(self):
        if self['endpoint'] is None:
            raise usage.UsageError("Must specify a connection endpoint.")
        if self['proxied-url'] is None:
            raise usage.UsageError("Must specify base URL to proxy.")
        if self['cas-login'] is None:
            raise usage.UsageError("Must specify CAS login URL.")
        if self['cas-service-validate'] is None:
            login = self['cas-login']
            parts = login.split('/')
            parts[-1] = "serviceValidate"
            serviceValidate = '/'.join(parts)
            self['cas-service-validate'] = serviceValidate
            del parts
            del login

class MyServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "casproxy"
    description = "CAS Authenticating Proxy"
    options = Options

    def makeService(self, options):
        """
        """
        cas_info = dict(
            login_url=options['cas-login'],
            service_validate_url=options['cas-service-validate'])
        fqdn = options.get('fqdn', None)
        # Create the service.
        return ProxyService(
            endpoint_s=options['endpoint'], 
            proxied_url=options['proxied-url'],
            cas_info=cas_info,
            fqdn=fqdn,
            authorities=options['authorities']) 

# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.

serviceMaker = MyServiceMaker()
