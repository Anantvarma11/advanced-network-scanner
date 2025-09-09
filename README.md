# Advanced Network Scanner

An advanced automated network discovery and port scanning tool with real-time topology visualization, OS & device fingerprinting, critical port alerts, and an interactive dashboard.

Built with Python, Scapy, Dash, Plotly, and Docker for easy deployment.

## Features
- Live ICMP ping sweep and threaded TCP SYN port scanning
- Service detection for common ports (SSH, HTTP/S, RDP, etc.)
- OS and device-type heuristics
- Real-time Dash dashboard with topology graph and metrics
- Export results to CSV on each scan cycle
- Critical port alerts (e.g. 22/23/3389)

## Repository Structure
```
│── scanner.py
│── requirements.txt
│── Dockerfile
│── README.md
│── .gitignore
│
├── docs/
│   └── SETUP.md
│
├── examples/
│   └── sample_report.csv
│
├── scripts/
│   └── run.sh
```

## Quickstart

### Local (Python)
```bash
pip install -r requirements.txt
python scanner.py
```

The dashboard starts on http://localhost:8050

### Docker
```bash
docker build -t prod-network-scanner .
docker run -p 8050:8050 --network host prod-network-scanner
```

Note: On macOS/Windows, `--network host` behaves differently; consider mapping ports without host networking if needed.

## Usage Tips
- The app performs repeated scans (default every 5 minutes). CSV reports are written to the working directory.
- Use the dashboard filters to focus on device types and services of interest.
- Click a node in the graph to view host details and any critical port alerts.

## Requirements
See `requirements.txt`. Scapy may require libpcap/pcap headers on your OS.

## Troubleshooting
- Permission issues for raw sockets: run with elevated privileges (e.g., `sudo`) or use Docker.
- No interfaces detected: ensure your network interface is up and you have gateway info.
- Slow scans: reduce `ports_to_scan` or `max_threads` in `scanner.py`.

## License
MIT
