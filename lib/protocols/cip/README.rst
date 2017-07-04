================================
Ethernet/IP dissectors for Scapy
================================

This repository contains a Python library which can be used to interact with components of a network using ENIP (Ethernet/IP) and CIP (Common Industrial Protocol) protocols.
It uses scapy (http://www.secdev.org/projects/scapy/) to implement packet dissectors which are able to decode a part of the network traffic.
These dissectors can also be used to craft packets, which allows directly communicating with the PLCs (Programmable Logic Controllers) of the network.

This project has been created to help analyzing the behavior of SWaT, a water treatment testbed built at SUTD (Singapore University of Technology and Design). For more information on our work, visit http://scy-phy.net

Therefore, it mostly implements a subset of CIP specification, which is used in this system.


Requirements
============

* Python 2.7
* Scapy (http://www.secdev.org/projects/scapy/)


Example of packet decoding
==========================

Here is the raw content of a packet sent to a PLC to query a tag (in SWaT), as seen by an hexadecimal viewer::

    00000000: 801d 9cc8 bde7 001d 9cc6 72e8 0800 4500  ..........r...E.
    00000010: 005e 2f95 4000 8006 4746 c0a8 0164 c0a8  .^/.@...GF...d..
    00000020: 010a c203 af12 8e7a 4387 01bd 1e5e 5018  .......zC....^P.
    00000030: 829c 2a07 0000 7000 1e00 0200 1600 0000  ..*...p.........
    00000040: 0000 0000 0000 0000 0000 0000 0000 0000  ................
    00000050: 0000 0000 0200 a100 0400 2042 b5ff b100  .......... B....
    00000060: 0a00 8a07 4c03 20b2 2500 2200            ....L. .%.".

This packet can be decoded using this Python script:

.. code-block:: python

    #!/usr/bin/env python2
    import binascii
    from scapy.all import *
    import cip

    rawpkt = binascii.unhexlify(
        '801d9cc8bde7001d9cc672e808004500005e2f95400080064746c0a80164'
        'c0a8010ac203af128e7a438701bd1e5e5018829c2a07000070001e000200'
        '1600000000000000000000000000000000000000000000000200a1000400'
        '2042b5ffb1000a008a074c0320b225002200')
    pkt = Ether(rawpkt)
    pkt.show()

This script prints the structure of the packet with every protocol layer (Ethernet, IP, ENIP and CIP)::

    ###[ Ethernet ]###
      dst       = 00:1d:9c:c8:bd:e7
      src       = 00:1d:9c:c6:72:e8
      type      = 0x800
    ###[ IP ]###
         version   = 4L
         ihl       = 5L
         tos       = 0x0
         len       = 94
         id        = 12181
         flags     = DF
         frag      = 0L
         ttl       = 128
         proto     = tcp
         chksum    = 0x4746
         src       = 192.168.1.100
         dst       = 192.168.1.10
         \options   \
    ###[ TCP ]###
            sport     = 49667
            dport     = EtherNet_IP_2
            seq       = 2390377351
            ack       = 29171294
            dataofs   = 5L
            reserved  = 0L
            flags     = PA
            window    = 33436
            chksum    = 0x2a07
            urgptr    = 0
            options   = []
    ###[ ENIP_TCP ]###
               command_id= SendUnitData
               length    = 30
               session   = 1441794
               status    = success
               sender_context= 0
               options   = 0
    ###[ ENIP_SendUnitData ]###
                  interface_handle= 0
                  timeout   = 0
                  count     = 2
                  \items     \
                   |###[ ENIP_SendUnitData_Item ]###
                   |  type_id   = conn_address
                   |  length    = 4
                   |###[ ENIP_ConnectionAddress ]###
                   |     connection_id= 4290069024
                   |###[ ENIP_SendUnitData_Item ]###
                   |  type_id   = conn_packet
                   |  length    = 10
                   |###[ ENIP_ConnectionPacket ]###
                   |     sequence  = 1930
                   |###[ CIP ]###
                   |        direction = request
                   |        service   = Read_Tag_Service
                   |        \path      \
                   |         |###[ CIP_Path ]###
                   |         |  wordsize  = 3
                   |         |  path      = class 0xb2,instance 0x22
                   |        \status    \

Moreover, each component of the packet is accessible in Python.
For example, adding ``print(pkt[cip.CIP].path)`` at the end of the script shows the path of the tag being queried in this CIP request::

    [<CIP_Path  wordsize=3 path=class 0xb2,instance 0x22 |>]


Interfacing with a PLC
======================

The scapy dissectors can be used to craft packet and therefore communicate with a PLC using ENIP and CIP.
These communications require several handshakes:

* a TCP handshake to establish a communication channel,
* an ENIP handshake to register an ENIP session,
* an optional CIP handshake (with ForwardOpen messages).

The file ``plc.py`` provides ``PLCClient`` class, which implements an abstraction level of the state of a communication with a PLC.
Here is for example how to use this class to read tag ``HMI_LIT101`` on the PLC sitting at address ``192.168.1.10``:

.. code-block:: python

    import logging
    import sys

    from cip import CIP, CIP_Path
    import plc

    logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

    # Connect to PLC
    client = plc.PLCClient('192.168.1.10')
    if not client.connected:
        sys.exit(1)
    print("Established session {}".format(client.session_id))

    if not client.forward_open():
        sys.exit(1)

    # Send a CIP ReadTag request
    cippkt = CIP(service=0x4c, path=CIP_Path.make_str("HMI_LIT101"))
    client.send_unit_cip(cippkt)

    # Receive the response and show it
    resppkt = client.recv_enippkt()
    resppkt[CIP].show()

    # Close the connection
    client.forward_close()
