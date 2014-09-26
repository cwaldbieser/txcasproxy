
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
                    ]

    def __init__(self):
        usage.Options.__init__(self)

    def postOptions(self):
        if self['endpoint'] is None:
            raise usage.UsageError("Must specify a connection endpoint.")

class MyServiceMaker(object):
    implements(IServiceMaker, IPlugin)
    tapname = "casproxy"
    description = "CAS Authenticating Proxy"
    options = Options

    def makeService(self, options):
        """
        """
        # Create the service.
        return ProxyService(endpoint_s=options['endpoint']) 

# Now construct an object which *provides* the relevant interfaces
# The name of this variable is irrelevant, as long as there is *some*
# name bound to a provider of IPlugin and IServiceMaker.

serviceMaker = MyServiceMaker()
