"""
Python Ctypes wrapper for EXPLOITMANAGER.  No additional levels of abstraction
added.  Interface using ctypes types and variables.

Notes: Incomplete. Only import/export XML file functions have been defined
"""


#from ctypes import *
import ctypes
import sys

try:
    mswindows = (sys.platform == "win32")

    _libraries = {}

    if mswindows:
        _libraries['exma.dll'] = ctypes.CDLL('exma-1.dll')
    else:
        _libraries['exma.dll'] = ctypes.CDLL('libexma.so.1')


    STRING = ctypes.c_char_p
    SOCKET = ctypes.c_uint

    getDefaultEMFile = _libraries['exma.dll'].getDefaultEMFile
    getDefaultEMFile.restyp   = STRING
    getDefaultEMFile.argtypes = []

    readParamsFromEM = _libraries['exma.dll'].readParamsFromEM
    readParamsFromEM.restype  = STRING
    readParamsFromEM.argtypes = [STRING]

    writeParamsToEM = _libraries['exma.dll'].writeParamsToEM
    writeParamsToEM.restype  = ctypes.c_int
    writeParamsToEM.argtypes = [STRING, STRING]

    bindRendezvous = _libraries['exma.dll'].bindRendezvous
    bindRendezvous.restype  = ctypes.c_int
    bindRendezvous.argtypes = [ctypes.POINTER(ctypes.c_ushort), ctypes.POINTER(SOCKET)]

    sendSockets = _libraries['exma.dll'].sendSockets
    sendSockets.restype  = ctypes.c_int
    sendSockets.argtypes = [SOCKET]

    closeRendezvous = _libraries['exma.dll'].closeRendezvous
    closeRendezvous.restype  = ctypes.c_int
    closeRendezvous.argtypes = [ctypes.c_ushort, SOCKET]

    connectRendezvous = _libraries['exma.dll'].connectRendezvous
    connectRendezvous.restype  = ctypes.c_int
    connectRendezvous.argtypes = [ctypes.c_ushort, ctypes.POINTER(SOCKET)]

    recvSocket = _libraries['exma.dll'].recvSocket
    recvSocket.restype  = ctypes.c_int
    recvSocket.argtypes = [SOCKET, SOCKET, ctypes.POINTER(SOCKET)]

    disconnectRendezvous = _libraries['exma.dll'].disconnectRendezvous
    disconnectRendezvous.restype  = ctypes.c_int
    disconnectRendezvous.argtypes = [SOCKET]

    writeParamsToEM = _libraries['exma.dll'].writeParamsToEM
    writeParamsToEM.restype = ctypes.c_int
    writeParamsToEM.argtypes = [ctypes.c_int, STRING]

    openEMForWriting = _libraries['exma.dll'].openEMForWriting
    openEMForWriting.restype = ctypes.c_int
    openEMForWriting.argtypes = [STRING]

except:

    def getDefaultEMFile(*args):
        print "[!] getDefaultEMFile"
        print args

    def readParamsFromEM(*args):
        f = open(str(args[0]))
        return str(f.read())

    def writeParamsToEM(*args):
        print "[!] writeParamsToEM"
        print args


    def bindRendezvous(*args):
        print "[!] bindRendezvous"
        print args

    def sendSockets(*args):
        print "[!] sendSockets"
        print args

    def closeRendezvous(*args):
        print "[!] closeRendezvous"
        print args

    def connectRendezvous(*args):
        print "[!] connectRendezvous"
        print args

    def recvSocket(*args):
        print "[!] recvSocket"
        print args

    def disconnectRendezvous(*args):
        print "[!] disconnectRendezvous"
        print args

    def writeParamsToEM(*args):
        print "[!] writeParamsToEM"
        print args

    def openEMForWriting(*args):
        # _libraries['exma.dll'] = ctypes.CDLL('exma-1.dll')
        print "[!] openEMForWriting"
        print args


__all__ = ['getDefaultEMFile', 'readParamsFromEM', 'writeParamsToEM',
           'bindRendezvous', 'sendSockets', 'closeRendezvous',
           'connectRendezvous', 'recvSocket', 'disconnectRendezvous',
		   'writeParamsToEM', 'openEMForWriting']



