from scapy.packet import Packet, bind_layers
from scapy.fields import IntEnumField, IntField, ShortField
from scapy.layers.inet import IP, TCP, UDP
import enum

class NIPktType(enum.IntEnum):
    ACK = 0
    READ = 1
    WRITE = 2
    RESPONSE = 3

class NIHeader(Packet):
    name = "NIHeader"
    fields_desc = [
        IntField("level", 0),
        ShortField("enc", 0),
        ShortField("nh", 0),
        IntField("session", 0),
        IntEnumField("pkt_type", 0, NIPktType),
    ]

bind_layers(IP, NIHeader, proto=254)
bind_layers(NIHeader, TCP, nh=6)
bind_layers(NIHeader, UDP, nh=17)