import libsocket
from threading import Thread

class Node_Server(libsocket.Server):
    def __init__(self, port=6438, host='0.0.0.0'):
        super().__init__(port, host)
        self._connections = []

class Node_Client(libsocket.Client):
    def __init__(self, port=6438, host='chaxiraxi.ch', timeout=10):
        super().__init__(port, host, timeout)
        self._connections = []
