"""Test-host accommodation only: suppress network interface/route discovery.
Packet serialization, capture I/O, DNS parsing and detector are unmodified.
"""
from unittest.mock import patch
from scapy.config import conf
conf.route_autoload=False
conf.route6_autoload=False
with patch('scapy.interfaces.NetworkInterfaceDict.reload',lambda self:None):
    import scapy.all
