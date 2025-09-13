from scapy.all import sniff, Raw, get_if_list
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from collections import defaultdict 
import queue 
import threading 
from sklearn.ensemble import IsolationForest
import numpy as np 
import logging 
import json 
from datetime import datetime

class packetCapt:
    def __init__(self):
        # Initialize a lass to start the packet capture and set an event stop for threading
        self.packet_queue = queue.Queue()
        self.stop_queue = threading.Event()
        self.capt_thread = None


    def pack_callB(self, packet):
        # Check if the packet contains IP and TCP componenets, if so then add it to the queue
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)

    def capt_thread(self, interface):
        try:
            sniff(iface=interface, prn=self.pack_callB, store=0,
                  stop_filter=lambda x: self.stop_queue.is_set())
        except Exception as e:
            print(f"packet capture error: {e}")
    
    def Begin_capt(self, interface="eth0"):
        # Handle packet capture with sniff() with an interface of eth0 whichi is our local etho network
        print(f"Booting up packet capture on interface: {interface}")

        self.capt_thread = threading.Thread(target=self.capt_thread, args=(interface,))
        self.capt_thread.daemon = True
        self.capt_thread.start()

    def stop(self):
        # Set the capture stop event and join it with the threading event to stop whenever the threading stops.

        print("shutting packet capture down...")
        self.stop_queue.set()
        if self.capt_thread and self.capt_thread.is_alive():
            self.capt_thread.join(timeout=3)

class traffic:
    def __init__(self):
        self.connect = defaultdict(list) # organize connections and flow statistics with deafultdict
        self.statistical_flow = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })
        
    def pack_analysis(self, packet):
        # proccess each type of packet by extracting src and destionation IPS and poorts 
        # Use the extracted information to form a unique identifier key
        if TCP in packet and IP in packet:
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport 
            ip_src = packet[IP].src 
            ip_dst = packet[IP].dst

            key_flow = (ip_src, ip_dst, port_src, port_dst)

            stats = self.statistical_flow[key_flow]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            curr_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = curr_time
            stats['last_time'] = curr_time

            return self.extract_feat(packet, stats)
        
    def extract_feat(self, packet, stats):
        # Computer extra detailed characteristics of the flow and current packet to help 
        # identify potential threats, anamolies, and patterns

        duration = stats['last_time'] - stats['start_time']
        if duration <= 0:
            duration = 0.00001


        return {
            'packet_size': len(packet),
            'flow_duration':duration,
            'packet_rate': stats['packet_count'] / duration,
            'byte_rate': stats['byte_count'] / duration,
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window 
        
        }
    

class EngineDetect:
    def __init__(self):
        self.anomaly_detect = IsolationForest(
            contamination = 0.1,
            random_state = 42
        )

        self.sgn_rules = self.load_sgn_rules()
        self.training_data = []

    def load_sgn_rules(self):
        return {
            'syn_flood': {
                'condition': lambda features: {
                    features['tcp_flags'] == 2 and 
                    features['packet_rate'] > 100
                }
            },

            'port_scan': {
                'condition': lambda features:{
                    features['packet_size'] < 100 and 
                    features['packet_rate'] > 50
                }
            }
        }
    
    def train_AnomDet(self, norm_traffic):
        self.anomaly_detect.fit(norm_traffic)
    
    def threat_detection(self, features):
        threats = []

        # Apply conditioning for signature baded detection
        for rule_name, rule in self.sgn_rules.items():
            if rule['condition'](features):
                threats.append({
                    'type': 'signature',
                    'rule': rule_name,
                    'confidence': 1.0
                })

        # Apply conditioning for anomaly based detections 
        vectFeature = np.array([[
            features['packet_size'],
            features['packet_rate'],
            features['byte_rate']
        ]])

        anomaly_score = self.anomaly_detect.score_samples(vectFeature)[0]
        if anomaly_score  < -0.5: # Provide an anomaly threshold for detections
            threats.append({
                'type': 'anomaly',
                'score': anomaly_score, 
                'confidence': min(1.0, abs(anomaly_score))
            })

        return threats
    

class Alert:
    def __init__(self, log_file="IDS_alerts.log"):
        self.logger = logging.getLogger("IDS_Alerts")
        self.logger.setLevel(logging.INFO)

        LogHandler = logging.FileHandler(log_file)
        LogFormatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        )

        LogHandler.setFormatter(LogFormatter)
        self.logger.addHandler(LogHandler)


    def Alert_generator(self, threat, packet_info):
        alert = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'source_ip': packet_info.get('source_ip'),
            'destination_ip': packet_info.get('destination.ip'),
            'confidence': threat.get('confidence', 0.0),
            'details': threat
        }

        self.logger.warning(json.dumps(alert))

        if threat['confidence'] > 0.8:
            self.logger.critical(
                f" HIGH CONFIDENCE THREAT DETECTED: {json.dumps(alert)} "
            )
        


class IDS:
    def __init__(self, interface="eth0"):
        self.packet_capt = packetCapt()
        self.traffic_analy = traffic()
        self.detect_sys = EngineDetect()
        self.alert_sys = Alert()
        self.interface = interface

    
    def start(self):
        print(f" Initialising IDS on interface {self.interface}")
        self.packet_capt.Begin_capt(self.interface)

        while True:
            try:
                packet = self.packet_capt.packet_queue.get(timeout=2)
                features = self.traffic_analy.pack_analysis(packet)

                if features:
                    threats = self.detect_sys.threat_detection(features)

                    for threat in threats:
                        packet_info = {
                            'source_ip': packet[IP].src,
                            'destination_ip': packet[IP].dst,
                            'source_port': packet[TCP].sport,
                            'destination_port': packet[TCP].dport
                        }
                        self.alert_sys.Alert_generator(threat,packet_info)

            except queue.Empty:
                continue 
            except KeyboardInterrupt:
                print("Stopping IDS...")
                self.packet_capt.stop()
                break


if __name__ == "__main__":
    ids = IDS()
    ids.start()


