#!/usr/bin/env python3
import os
import sys
from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import threading
import queue
import time
import argparse

def check_root():
    if os.geteuid() != 0:
        print("This script requires root privileges to capture network packets.")
        print("Please run the script using:")
        print(f"sudo {sys.executable} {os.path.abspath(__file__)}")
        sys.exit(1)

def list_interfaces():
    interfaces = get_if_list()
    print("\nAvailable network interfaces:")
    for iface in interfaces:
        print(f"- {iface}")
    sys.exit(0)

class NetworkAnalyzer:
    def __init__(self):
        self.packet_queue = queue.Queue()
        self.packets = []
        self.is_capturing = False
        self.protocol_stats = {}
        self.bandwidth_stats = []
        self.suspicious_patterns = [
            ('port', 22),  # SSH brute force attempts
            ('port', 3389),  # RDP attacks
            ('port', 445),  # SMB attacks
        ]

    def packet_callback(self, packet):
        if packet.haslayer(IP):
            packet_info = {
                'timestamp': datetime.now(),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'length': len(packet),
                'sport': packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else None,
                'dport': packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else None
            }
            self.packet_queue.put(packet_info)

    def analyze_protocols(self):
        while self.is_capturing:
            try:
                packet = self.packet_queue.get(timeout=1)
                self.packets.append(packet)
                
                # Update protocol statistics
                protocol = packet['protocol']
                self.protocol_stats[protocol] = self.protocol_stats.get(protocol, 0) + 1
                
                # Check for suspicious activity
                self.check_suspicious_activity(packet)
                
                # Update bandwidth statistics
                self.update_bandwidth_stats(packet)
                
            except queue.Empty:
                continue

    def check_suspicious_activity(self, packet):
        for pattern_type, pattern_value in self.suspicious_patterns:
            if pattern_type == 'port' and (packet['sport'] == pattern_value or packet['dport'] == pattern_value):
                print(f"\033[91mSuspicious activity detected: Port {pattern_value} ({datetime.now()})\033[0m")

    def update_bandwidth_stats(self, packet):
        current_time = datetime.now()
        self.bandwidth_stats.append({
            'timestamp': current_time,
            'bytes': packet['length']
        })
        
        # Print real-time bandwidth stats every 5 seconds
        if len(self.bandwidth_stats) % 50 == 0:
            recent_bytes = sum(stat['bytes'] for stat in self.bandwidth_stats[-50:])
            print(f"\033[92mCurrent bandwidth usage: {recent_bytes/1024:.2f} KB/s\033[0m")

    def start_capture(self, interface="wlo1"):
        print(f"\033[94mStarting network capture on interface {interface}...\033[0m")
        print("Press Ctrl+C to stop and generate report")
        
        self.is_capturing = True
        capture_thread = threading.Thread(target=self.analyze_protocols)
        capture_thread.start()
        
        try:
            sniff(iface=interface, prn=self.packet_callback, store=0)
        except KeyboardInterrupt:
            self.stop_capture()
        except OSError as e:
            print(f"\033[91mError: Could not capture on interface {interface}")
            print("Available interfaces:")
            for iface in get_if_list():
                print(f"- {iface}")
            sys.exit(1)

    def stop_capture(self):
        print("\n\033[94mStopping capture and generating report...\033[0m")
        self.is_capturing = False
        self.generate_report()

    def generate_report(self):
        if not self.packets:
            print("\033[93mNo packets captured!\033[0m")
            return

        # Convert packets to DataFrame
        df = pd.DataFrame(self.packets)
        
        # Protocol distribution
        plt.figure(figsize=(10, 6))
        plt.pie(self.protocol_stats.values(), labels=self.protocol_stats.keys(), autopct='%1.1f%%')
        plt.title('Protocol Distribution')
        plt.savefig('protocol_distribution.png')
        plt.close()

        # Bandwidth usage over time
        if self.bandwidth_stats:
            bw_df = pd.DataFrame(self.bandwidth_stats)
            plt.figure(figsize=(12, 6))
            plt.plot(bw_df['timestamp'], bw_df['bytes'])
            plt.title('Bandwidth Usage Over Time')
            plt.xlabel('Time')
            plt.ylabel('Bytes')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig('bandwidth_usage.png')
            plt.close()

        # Print summary statistics
        print("\n\033[94mNetwork Analysis Summary:\033[0m")
        print(f"Total packets captured: {len(self.packets)}")
        print("\nProtocol Statistics:")
        for protocol, count in self.protocol_stats.items():
            print(f"Protocol {protocol}: {count} packets")
        
        if self.bandwidth_stats:
            total_bytes = sum(bw['bytes'] for bw in self.bandwidth_stats)
            print(f"\nTotal traffic: {total_bytes/1024/1024:.2f} MB")
            
        print("\nReport files generated:")
        print("- protocol_distribution.png")
        print("- bandwidth_usage.png")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Network Traffic Analyzer')
    parser.add_argument('-i', '--interface', default='wlo1', help='Network interface to capture packets from')
    parser.add_argument('-l', '--list', action='store_true', help='List available network interfaces')
    args = parser.parse_args()

    if args.list:
        list_interfaces()

    check_root()
    analyzer = NetworkAnalyzer()
    analyzer.start_capture(interface=args.interface) 