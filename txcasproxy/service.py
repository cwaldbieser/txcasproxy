
# Standard library.
import sys

# Application modules
from txcasproxy import ProxyApp

# External modules
from twisted.application.service import Service
from twisted.internet import reactor
from twisted.internet.endpoints import serverFromString
from twisted.web.server import Site

class ProxyService(Service):
    """
    Service 
    """

    def __init__(
            self, 
            endpoint_s, 
            proxied_url, 
            cas_info, 
            fqdn=None, 
            authorities=None,
            plugins=None): 
        """
        """
        self.port_s = endpoint_s

        # Create the application. 
        cas_info = cas_info
        app = ProxyApp(
            proxied_url, 
            cas_info, 
            fqdn=fqdn, 
            authorities=authorities,
            plugins=plugins)
        root = app.app.resource()
        self.app = app
        self.site = Site(root)

    def startService(self):
        if self.port_s is not None:
            #----------------------------------------------------------------------
            # Create endpoint from string.
            #----------------------------------------------------------------------
            endpoint = serverFromString(reactor, self.port_s)
            d = endpoint.listen(self.site)
            d.addCallback(self.register_port)
            
    def register_port(self, lp):
        """
        """
        host = lp.getHost()
        print "Setting port %d ..." % host.port
        self.app.port = host.port
        self.app.handle_port_set()
