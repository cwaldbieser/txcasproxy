
from autobahn.twisted.resource import WebSocketResource
from autobahn.twisted.websocket import (
    WebSocketServerFactory,
    WebSocketServerProtocol,
    WebSocketClientFactory,
    WebSocketClientProtocol
)


class ProxiedWSClientProtocol(WebSocketClientProtocol):
    connectedToProxy = False
    onMessageCallback = None
    maxQueueSize = 100

    def __init__(self):
        self._queue = []

    def onOpen(self):
        self.connectedToProxy = True
        for msg, isBinary in self._queue:
            self.sendMessage(msg, isBinary)

    def sendMessageToProxiedWS(self, msg, isBinary):
        if self.connectedToProxy:
            self.sendMessage(msg.encode('utf8'), isBinary)
        else:
            q = self._queue
            if len(q) < self.maxQueueSize:
                q.append((msg.encode('utf8'), isBinary))
            else:
                raise Execption("Queue overflow error.")

   def onMessage(self, payload, isBinary):
        self.onMessageCallback(payload, isBinary)


class ProxiedWSClientProtocolFactory(WebSocketClientFactory):
    protocol = ProxiedWSClientProtocol
    onMessage = None

    def buildProtocol(self, addr):
        proto = self.protocol()
        proto.onMessageCallback = self.onMessage


class WSProxyProtocol(WebSocketServerProtocol):
    debug = False
    reactor = None
    _proxied_websocket = Nonw

    def __init__(self, target_url, reactor=None):
        """
        target_url: showuld be a websocket URL, e.g. 'ws://127.0.0.1:9000'
        """
        if self.reactor is None:
            from twisted.internet import reactor
            self.reactor = reactor
        wsfactory = ProxiedWSClientProtocolFactor(target_url, debug=self.debug)
        wsfactory.onMessage = self.sendMessage
        self._wsfactory = wsfactory
        ws_endpoint_str = self._compute_endpoint_from_url(target_url)
        wsclient = clientFromString(self.reactor, ws_endpoint_str)
        d = wsclient.connect(wsfactory)
        d.addCallback(self.handleConnected)

    def handleConnected(self, proto):
        self._proxied_websocket = proto
        
    def _compute_endpoint_from_url(self, url):
        """
        Compute the Twisted endpoint (e.g. 'tcp:127.0.0.1:9000') from the
        websocket URL (e.g. 'ws://127.0.0.1:9000').
        """
        # TODO:

    def onMessage(self, payload, isBinary):
        self.proxied_websocket.sendMessageToProxiedWS(payload, isBinary)
