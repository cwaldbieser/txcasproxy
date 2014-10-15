

# External modules
from zope.interface import Interface, Attribute

class IRProxyPluginFactory(Interface):
    
    def generatePlugin(argstring=""):
        """
        Create a plugin from string arguments.
        """

class IRProxyInfoAcceptor(Interface):
    
    proxy_fqdn = Attribute("Proxy fqdn.")
    proxy_port = Attribute("Proxy port.")
    proxied_netloc = Attribute("Proxied netloc.")
    proxied_path = Attribute("Proxied path.")
    
    def handle_rproxy_info_set():
        """
        Event triggered after reverse proxy information has been set.
        """

class IResponseContentModifier(Interface):
    
    mod_sequence = Attribute('Sequence number.')
    
    def transform_content(content, request):
        """
        Transform `content`
        """

class ICASRedirectHandler(Interface):
    
    cas_redirect_sequence = Attribute("Sequence number.")
    
    def intercept_service_url(service_url, request):
        """
        Inspect and return a modified or unmodified service URL.
        """
