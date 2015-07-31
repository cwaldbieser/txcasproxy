
from klein import Klein
from twisted.web.server import Site
import json

class AuthInfoApp():
    app = Klein()

    def __init__(self):
        self.authinfo = {}

    @app.route("/<string:username>")
    def authinfo(self, request, username):
        if request.method != 'GET':
            request.setResponseCode(404)
            return "Not Found - 404"
        info = self.authinfo.get(username, None)
        if info is None:
            request.setResponseCode(404)
            return "Not Found - 404"
        serialized = json.dumps(info)
        request.responseHeaders.setRawHeaders('Content-Type', ['application/json'])
        return serialized

    def setAuthInfo(self, username, info):
        authinfo = self.authinfo
        if info is None:
            if username in authinfo:
                del authinfo[username]
        else:
            authinfo[username] = info

def makeAuthInfoSite():
    app = AuthInfoApp()
    root = app.app.resource()
    site = Site(root)
    return site 
