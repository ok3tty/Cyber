from scapy.all import sniff, IP, TCP 
from collections import defaultdict 
import queue 
import threading 


class packetCapt:
    def _init_(self):
        # Initialize a lass to start the packet capture and set an event stop for threading
        self.pack_queue = queue.Queue()
        self.stop_queue = threading.Event()


    def pack_callB(self, packet):
        # Check if the packet contains IP and TCP componenets, if so then add it to the queue
        if IP in packet and TCP in packet:
            self.pack_queue.put(packet)
    
    def Begin_capt(self, interface="eth0"):
        # Handle packet capture with sniff() with an interface of eth0 whichi is our local etho network
        def capt_thread():
            sniff(iface=interface, prn=self.pack_callB, store=0, stop_filter=lambda _: self.stop_queue.is_set())

        self.capt_thread = threading.Thread(target=capt_thread)
        self.capt_thread.start()

    def stop(self):
        # Set the capture stop event and join it with the threading event to stop whenever the threading stops.

        self.stop_queue.set()
        self.capt_thread.join()

class traffic:
    def _init_(self):
        self.connect = defaultdict(list)
        self.statistical_flow = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })
        
    def pack_analysis(self, packet):
        if TCP in packet and IP in packet:
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport 
            ip_src = packet[IP].src 
            ip_dst = packet[IP].dst

            key_flow = (ip_src, ip_dst, port_src, port_dst)

            stats = self.statistical_flow(key_flow)
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            curr_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = curr_time
            stats['last_time'] = curr_time

            return self.extract_feat(packet, stats)
        
    def extract_feat(self, packet, stats):
        return {
            'packet_size': len(packet),
            'flow_duration':stats['last_time'] - stats['start_time'],
            'packet_rate': stats['packet_count'] / (stats['last_time'] - stats['start_time']),
            'byte_rate': stats['byte_count'] / (stats['last_time'] - stats['start_time']),
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window 
        
        }

