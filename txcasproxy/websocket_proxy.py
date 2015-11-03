
import urlparse
from autobahn.twisted.resource import WebSocketResource
from autobahn.twisted.websocket import (
    WebSocketServerFactory,
    WebSocketServerProtocol,
    WebSocketClientFactory,
    WebSocketClientProtocol
)
from twisted.internet.endpoints import clientFromString
from twisted.python import log


class ProxiedWSClientProtocol(WebSocketClientProtocol):
    connectedToProxiedWS = False
    onMessageCallback = None
    onCloseCallback = None
    maxQueueSize = 100

    def __init__(self):
        WebSocketClientProtocol.__init__(self)
        self._queue = []

    def onConnect(self, r):
        log.msg("[EVENT] ProxiedWSClientProtocol.onConnect()")

    def onOpen(self):
        log.msg("[EVENT] ProxiedWSClientProtocol.onOpen()")
        self.connectedToProxiedWS = True
        log.msg("[DEBUG] Queue size={0}".format(len(self._queue)))
        for msg, isBinary in self._queue:
            log.msg("[DEBUG] Sending queued message to proxied ws ...")
            if not isBinary:
                log.msg("[DEBUG] msg='{0}'".format(msg))
            self.sendMessage(msg, isBinary)
        log.msg("[DEBUG] Resetting queue...")
        self._queue = []

    def sendMessageToProxiedWS(self, msg, isBinary):
        log.msg("[EVENT] sending message to proxied websocket ...")
        log.msg("[DEBUG] connected to proxied ws={0}".format(self.connectedToProxiedWS))
        if self.connectedToProxiedWS:
            self.sendMessage(msg.encode('utf8'), isBinary)
        else:
            q = self._queue
            if len(q) < self.maxQueueSize:
                q.append((msg.encode('utf8'), isBinary))
            else:
                raise Execption("Queue overflow error.")

    def onMessage(self, payload, isBinary):
        self.onMessageCallback(payload, isBinary)

    def onClose(self, wasClean, code, reason):
        self.onCloseCallback(wasClean, code, reason)


class ProxiedWSClientProtocolFactory(WebSocketClientFactory):
    protocol = ProxiedWSClientProtocol
    onMessage = None
    onClose = None

    def buildProtocol(self, addr):
        log.msg("[DEBUG] Creating ProxiedWSClientProtocol instance ...")
        proto = self.protocol()
        proto.onMessageCallback = self.onMessage
        proto.onCloseCallback = self.onClose
        proto.factory = self
        return proto


class WSProxyProtocol(WebSocketServerProtocol):
    debug = False
    reactor = None
    maxQueueSize = 100
    _proxied_websocket = None

    def __init__(self, ws_endpoint_str, target_url, origin=None, headers=None, reactor=None):
        """
        ws_endpoint_str: The proxied websocket endpoint string.
        target_url: should be a websocket URL, e.g. 'ws://127.0.0.1:9000'
        """
        WebSocketServerProtocol.__init__(self)
        self.ws_endpoint_str = ws_endpoint_str
        self.target_url = target_url
        self.origin = origin
        self.headers = headers
        self._queue = []
        if self.reactor is None:
            from twisted.internet import reactor
            self.reactor = reactor

    def connectToProxiedWebsocket(self):
        # TODO:
        #headers = {'Origin': 'http://localhost:8888/'} #debug
        wsfactory = ProxiedWSClientProtocolFactory(
            self.target_url, 
            origin=self.origin,
            headers=self.headers,
            debug=self.debug,
        )
        wsfactory.onMessage = self.sendMessage
        wsfactory.onClose = self.handleClose
        e = clientFromString(self.reactor, self.ws_endpoint_str)
        d = e.connect(wsfactory)
        d.addCallback(self.handleConnected)
         
        def _eb(err):
            log.msg("[ERROR] {0}".format(err))
            return err

        d.addErrback(_eb)

    def onConnect(self, r):
        log.msg("[EVENT] onConnect()")
        self.connectToProxiedWebsocket()

    def handleConnected(self, proto):
        log.msg("[EVENT] connected to proxied websocket.")
        self._proxied_websocket = proto
        for payload, isBinary in self._queue:
            log.msg("[DEBUG] iSending queued message to proxied websocket.")
            proto.sendMessageToProxiedWS(payload, isBinary)
        self._queue = []
        
    def onMessage(self, payload, isBinary):
        log.msg("[EVENT] onMessage()")
        if not isBinary:
            log.msg("[DEBUG] message payload='{0}'".format(payload))
        if self._proxied_websocket is not None:
            self._proxied_websocket.sendMessageToProxiedWS(payload, isBinary)
        else:
            q = self._queue
            if len(q) < self.maxQueueSize:
                q.append((payload, isBinary))
            else:
                raise Exception("Queue overflow.")

    def handleClose(self, wasClean, code, reason):
        log.msg("[EVENT] proxied websocket closed connection.  reason='{0}'".format(reason))
        #code = self.CLOSE_STATUS_CODE_GOING_AWAY
        #self.sendClose(code, reason)
        self._proxied_websocket = None


def _strip_query(url):
    p = urlparse.urlparse(url)
    temp = list(p)
    temp[4] = ''
    return urlparse.urlunparse(temp)

def makeWebsocketProxyResource(
        proxy_url, 
        proxied_ws_endpoint_str, 
        proxied_url, 
        request,
        origin=None, 
        reactor=None, 
        debug=False):
    log.msg("[DEBUG] proxied_ws_endpoint_str='{0}'".format(proxied_ws_endpoint_str))
    proxy_url = _strip_query(proxy_url)
    headers = dict((k, ' '.join(v)) for k, v in request.requestHeaders.getAllRawHeaders()
                if k in ['Cookie'])
    log.msg("[DEBUG] headers => {0}".format(headers))
    factory = WebSocketServerFactory(
        proxy_url,
        debug=debug,
        debugCodePaths=debug)
    factory.protocol = lambda : WSProxyProtocol(
        proxied_ws_endpoint_str, 
        proxied_url, 
        origin=origin,
        headers=headers,
        reactor=reactor,
    ) 
    resource = WebSocketResource(factory)
    return resource

