

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
    proxied_scheme = Attribute("Proxied scheme.")
    proxied_netloc = Attribute("Proxied netloc.")
    proxied_path = Attribute("Proxied path.")
    expire_session = Attribute("Expire a session.")
    
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

class IResourceInterceptor(Interface):
    
    interceptor_sequence = Attribute("Sequence number.")
    
    def should_resource_be_intercepted(url, method, headers, proxy_request):
        """
        Return True if resource should be intercepted.
        """
        
    def handle_resource(url, method, headers, proxy_request):
        """
        Return a deferred that fires the response body or a response body.
        """

class IStaticResourceProvider(Interface):
    
    static_resource_base = Attribute("Static resource base.")
    static_resource_dir = Attribute("Static resource folder.")

class ICASRedirectHandler(Interface):
    
    cas_redirect_sequence = Attribute("Sequence number.")
    
    def intercept_service_url(service_url, request):
        """
        Inspect and return a modified or unmodified service URL.
        """
