
# Standard library.
import sys

# Application modules
from txcasproxy import ProxyApp

# External modules
from twisted.application.service import Service
from twisted.internet.endpoints import serverFromString
from twisted.web.server import Site

class ProxyService(Service):
    """
    Service 
    """

    def __init__(self, endpoint_s): 
        """
        """
        self.port_s = endpoint_s

        # Create the application. 
        app = ProxyApp(target_url, cas_info)
        root = app.app.resource()

        self.site = Site(root)

    def startService(self):
        if self.port_s is not None:
            #----------------------------------------------------------------------
            # Create endpoint from string.
            #----------------------------------------------------------------------
            endpoint = serverFromString(reactor, self.port_s)
            endpoint.listen(self.site)

