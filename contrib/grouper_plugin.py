

#Standard library
from textwrap import dedent
import urllib
import urlparse

# Application modules
from txcasproxy.interfaces import IRProxyPluginFactory, IRProxyInfoAcceptor, \
                            IResourceModifier
from txcasproxy import proxyutils

# External modules
from twisted.plugin import IPlugin
from zope.interface import implements


class GrouperPluginFactory(object):
    """
    """
    implements(IPlugin, IRProxyPluginFactory)

    tag = "grouper"

    opt_help = dedent('''\
            Plugin for reverse proxying Internet2 Grouper UI.
            ''')

    opt_usage = '''Some options should go here ...'''

    def generatePlugin(self, argstring=""):
        """
        """
        kwds = {}
        return GrouperPlugin(**kwds) 

class GrouperPlugin(object):
    
    implements(IRProxyInfoAcceptor, IResourceModifier)
    
    proxy_fqdn = None
    proxy_port = 443
    proxied_netloc = '127.0.0.1:8443'
    proxied_path = '/'
    
    mod_sequence = 7
    
    owasp_js_servlet_resource = '/grouper/grouperExternal/public/OwaspJavaScriptServlet'
    
    def __init__(self, **kwds):
        self.kwds = kwds
        
    def handle_rproxy_info_set(self):
        pass
        
    def transform_content(self, content, request):
        """
        Transform `content`
        """
        if request.isSecure():
            scheme = 'https'
        else:
            scheme = 'http'
        p = urlparse.urlparse(request.uri)
        path = p.path
        params = p.params
        query = p.query
        fragment = p.fragment
        netloc = "%s:%d" % (self.proxy_fqdn, self.proxy_port)
        url = urlparse.urlunparse((scheme, netloc, path, params, query, fragment))
        proxied_url = proxyutils.proxy_url_to_proxied_url(
            self.proxy_fqdn, 
            self.proxy_port, 
            self.proxied_netloc, 
            self.proxied_path, 
            url)
        
        if proxied_url == self.owasp_js_servlet_resource:
            return self.csrf_js_hack(content)
            
        return content
            
    def csrf_js_hack(self, s):
        """
        """
        s = s.replace(self.proxied_host, self.fqdn)
        s = s.replace('''part = "/grouper/" + url;''', '''part = "/" + url;''')
        s = s.replace(
            self.owasp_js_servlet_resource, 
            self.owasp_js_servlet_resource[len(self.proxied_path):])
        return s
        
        
        
def qsmap_to_qslist(qsmap):
    for k, v in qsmap.iteritems():
        for item in v:
            yield (k, item)

        
