import pyshark as shark

class Sniffer:

    def __init__(self, inter):
        self.interface = inter

        self.capture = shark.LiveCapture(interface=self.interface)

    def print_conversation_header(self, pkt):
        try:
            protocol =  pkt.transport_layer
            src_addr = pkt.ip.src
            src_port = pkt[pkt.transport_layer].srcport
            dst_addr = pkt.ip.dst
            dst_port = pkt[pkt.transport_layer].dstport
            print '%s  %s:%s --> %s:%s' % (protocol, src_addr, src_port, dst_addr, dst_port)
            #return src_addr
        except AttributeError as e:
            #ignore packets that aren't TCP/UDP or IPv4
            pass

    def prints(self, count):
        if count == -1:
            self.capture.sniff(packet_count=1000000)
        else:
            self.capture.sniff(packet_count = count)
        return self.capture

        #self.capture.apply_on_packets(self.print_conversation_header, timeout=100)
