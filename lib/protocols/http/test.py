from scapy.all import *
from http import *
import socket


p = HTTPRequest()
p.setfieldval('Method', "GET")
p.setfieldval('Path', "/")
p.setfieldval('Host', "182.92.64.62")
p.show()

s = socket.socket()
s.connect(('182.92.64.62', 80))
s.send(str(p))
s.close()
