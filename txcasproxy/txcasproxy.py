#! /usr/bin/env python

#Standard library
import os.path

#External modules
from klein import Klein
import treq
#from twisted.internet.defer import inlineCallbacks
from twisted.web.static import File

class ProxyApp(object):
    app = Klein()

    def __init__(self):
        pass

    @app.route("/", branch=True)
    def proxy(self, request):
        """
        """
        kwds = {}
        kwds['headers'] = dict(request.requestHeaders.getAllRawHeaders())
        if request.method in ('PUT', 'POST'):
            kwds['data'] = request.content.read()
        print "kwds", kwds
        d = treq.request(request.method, 'http://parkland.tlcdelivers.com:8080' + request.uri, **kwds)
        def process_headers(response):
            for k,v in response.headers.getAllRawHeaders():
                request.responseHeaders.setRawHeaders(k, v)
            return response
        d.addCallback(process_headers)
        d.addCallback(treq.content)
        return d
    

if __name__ == "__main__":
    #Run standalone.
    import sys
    from twisted.python import log
    log.startLogging(sys.stdout)
 
    store = ProxyApp()
    store.app.run('127.0.0.1', 8080)
else:
    #Or with `twistd -y`
    from twisted.application import internet
    from twisted.application.service import Application
    from twisted.web.server import Site

    store = ProxyApp()
    resource = store.app.resource()

    application = Application("txShop")
    service = internet.TCPServer(8080, Site(resource))
    service.setServiceParent(application)

