# Network Traffic Analyzer

A real-time network traffic analysis tool with a web-based dashboard for monitoring and analyzing network packets.

## Features

- Real-time packet capture and analysis
- Protocol distribution visualization
- Bandwidth monitoring
- Active connections tracking
- Web-based dashboard with live updates
- Detailed packet information display

## Prerequisites

- Python 3.8 or higher
- Root/Administrator privileges (for packet capture)
- Network interface with packet capture capabilities

## Installation

1. Clone the repository:
```bash
git clone https://github.com/YOUR_USERNAME/Network_Analyzer.git
cd Network_Analyzer
```

2. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Start the dashboard with root privileges:
```bash
sudo python dashboard.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

## Project Structure

- `dashboard.py`: Main application file containing Flask server and packet capture logic
- `templates/index.html`: Web dashboard template
- `requirements.txt`: Python package dependencies

## Dependencies

- scapy: Network packet manipulation library
- flask: Web framework
- flask-socketio: WebSocket support for Flask
- eventlet: Asynchronous networking library

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 