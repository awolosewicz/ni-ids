from scapy.packet import Packet, bind_layers
from scapy.fields import IntField, ShortField, XLongField
from scapy.layers.inet import IP, TCP, UDP

class NIHeader(Packet):
    name = "NIHeader"
    fields_desc = [
        IntField("level", 0),
        ShortField("enc", 0),
        ShortField("nh", 0),
        XLongField("sig", 0)
    ]

bind_layers(IP, NIHeader, proto=254)
bind_layers(NIHeader, TCP, nh=6)
bind_layers(NIHeader, UDP, nh=17)