#!/usr/bin/env python3
from flask import Flask, render_template, jsonify
from flask_socketio import SocketIO
import threading
import queue
import json
from datetime import datetime
import os
import sys
from scapy.all import *
import argparse

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# Global variables
packet_queue = queue.Queue()
analyzer = None
capture_thread = None
stop_capture = threading.Event()

def packet_callback(packet):
    if packet.haslayer(IP):
        try:
            packet_info = {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': packet[IP].src,
                'dst_ip': packet[IP].dst,
                'protocol': packet[IP].proto,
                'length': len(packet),
                'sport': packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else None,
                'dport': packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else None
            }
            packet_queue.put(packet_info)
            socketio.emit('new_packet', packet_info)
        except Exception as e:
            print(f"Error processing packet: {e}")

def capture_packets(interface):
    try:
        sniff(iface=interface, prn=packet_callback, store=0, stop_filter=lambda _: stop_capture.is_set())
    except Exception as e:
        print(f"Error capturing packets: {e}")
        print("Available interfaces:", get_if_list())

def start_capture(interface="wlo1"):
    global capture_thread
    stop_capture.clear()
    capture_thread = threading.Thread(target=capture_packets, args=(interface,))
    capture_thread.daemon = True
    capture_thread.start()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def get_stats():
    stats = {
        'total_packets': packet_queue.qsize(),
        'protocol_stats': {},
        'bandwidth': 0
    }
    
    # Calculate recent bandwidth (last 5 seconds)
    recent_packets = []
    while not packet_queue.empty():
        packet = packet_queue.get()
        recent_packets.append(packet)
    
    if recent_packets:
        total_bytes = sum(p['length'] for p in recent_packets)
        stats['bandwidth'] = total_bytes / 1024  # Convert to KB
        
        # Update protocol stats
        for packet in recent_packets:
            proto = packet['protocol']
            stats['protocol_stats'][proto] = stats['protocol_stats'].get(proto, 0) + 1
            
        # Put packets back in queue
        for packet in recent_packets:
            packet_queue.put(packet)
    
    return jsonify(stats)

def check_root():
    if os.geteuid() != 0:
        print("This script requires root privileges to capture network packets.")
        print("Please run the script using:")
        print(f"sudo {sys.executable} {os.path.abspath(__file__)}")
        sys.exit(1)

def list_interfaces():
    print("\nAvailable network interfaces:")
    for iface in get_if_list():
        print(f"- {iface}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Network Traffic Dashboard')
    parser.add_argument('-i', '--interface', default='wlo1', help='Network interface to capture from')
    parser.add_argument('-l', '--list', action='store_true', help='List available network interfaces')
    args = parser.parse_args()

    if args.list:
        list_interfaces()
        sys.exit(0)

    check_root()
    print(f"Starting capture on interface {args.interface}")
    start_capture(args.interface)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True) 