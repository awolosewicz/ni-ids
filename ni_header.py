from scapy.packet import Packet, bind_layers
from scapy.fields import IntEnumField, IntField, ShortField, XLongField
from scapy.layers.inet import IP, TCP, UDP

class NIHeader(Packet):
    name = "NIHeader"
    fields_desc = [
        IntField("level", 0),
        ShortField("enc", 0),
        ShortField("nh", 0),
        IntField("session", 0),
        IntEnumField("pkt_type", 0, {0: "ACK", 1: "READ", 2: "WRITE", 3: "RESPONSE"}),
        XLongField("sig", 0)
    ]

bind_layers(IP, NIHeader, proto=254)
bind_layers(NIHeader, TCP, nh=6)
bind_layers(NIHeader, UDP, nh=17)