# 🔒 Network Security Scanner Suite

**Professional Cybersecurity Tool for Network Analysis and Security Assessment**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](https://github.com/your-username/network-security-scanner)


## 📖 Description

A comprehensive network security analysis toolkit developed with Python and modern GUI. This project demonstrates practical skills in cybersecurity, network programming, and GUI development - perfect for professional portfolios and technical interviews.

## ⚡ Key Features

### 🔍 Network Discovery
- **Host Discovery** - Find active devices on the network
- **Port Scanning** - Identify open ports and services
- **Service Detection** - Discover running services
- **OS Fingerprinting** - Identify operating systems

### 🛡️ Security Analysis
- **Vulnerability Scanning** - Identify security weaknesses
- **SSL/TLS Analysis** - Certificate and encryption validation
- **Banner Grabbing** - Service information collection
- **Network Mapping** - Network topology visualization

### 📊 Reporting & Visualization
- **Real-time Dashboard** - Live scan monitoring
- **Detailed Reports** - HTML/PDF report generation
- **Export Options** - JSON, CSV, XML formats
- **Visual Network Maps** - Interactive network graphs

### 🎨 Modern Interface
- **Tkinter GUI** - Clean and functional interface
- **Multi-threaded** - Optimized performance
- **Progress Tracking** - Real-time process status
- **Log System** - Detailed activity logging

## 🏗️ Project Architecture

```

network-security-scanner/

├── [main.py](http://main.py)                     # Application entry point

├── requirements.txt            # Python dependencies

├── config/

│   ├── **init**.py

│   ├── [settings.py](http://settings.py)            # Configuration settings

│   └── logging_[config.py](http://config.py)      # Logging configuration

├── core/

│   ├── **init**.py

│   ├── [scanner.py](http://scanner.py)             # Core scanning engine

│   ├── network_[discovery.py](http://discovery.py)   # Network discovery module

│   ├── port_[scanner.py](http://scanner.py)        # Port scanning functionality

│   ├── ssl_[analyzer.py](http://analyzer.py)        # SSL/TLS analysis

│   └── vulnerability_[scanner.py](http://scanner.py) # Vulnerability detection

├── gui/

│   ├── **init**.py

│   ├── main_[window.py](http://window.py)         # Main application window

│   ├── scanner_[tab.py](http://tab.py)         # Scanner interface tab

│   ├── results_[tab.py](http://tab.py)         # Results display tab

│   ├── reports_[tab.py](http://tab.py)         # Reports generation tab

│   └── settings_[tab.py](http://tab.py)        # Settings configuration tab

├── utils/

│   ├── **init**.py

│   ├── report_[generator.py](http://generator.py)    # Report generation utilities

│   ├── network_[utils.py](http://utils.py)       # Network utility functions

│   └── file_[manager.py](http://manager.py)        # File management utilities

├── data/

│   ├── common_ports.json      # Common port definitions

│   ├── service_signatures.json # Service detection signatures

│   └── vulnerability_db.json  # Vulnerability database

├── tests/

│   ├── **init**.py

│   ├── test_[scanner.py](http://scanner.py)        # Scanner module tests

│   ├── test_network_[discovery.py](http://discovery.py) # Network discovery tests

│   └── test_ssl_[analyzer.py](http://analyzer.py)   # SSL analyzer tests

├── docs/

│   ├── [installation.md](http://installation.md)        # Installation guide

│   ├── [usage.md](http://usage.md)              # Usage documentation

│   └── api_[reference.md](http://reference.md)      # API documentation

└── [README.md](http://README.md)                  # This file

```

## 💻 Technologies Used

- **Python 3.8+** - Programming language
- **Tkinter** - GUI framework
- **socket** - Network programming
- **threading** - Multi-threading support
- **requests** - HTTP requests
- **cryptography** - SSL/TLS analysis
- **matplotlib** - Data visualization
- **reportlab** - PDF generation
- **beautifulsoup4** - HTML parsing
- **netifaces** - Network interfaces

## 🔧 Installation & Setup

### Prerequisites

- Python 3.8 or higher
- pip package manager
- Administrative privileges (for some network operations)

### Installation Steps

```

# Clone the repository

git clone https://github.com/yourusername/network-security-scanner.git

cd network-security-scanner

# Create virtual environment

python -m venv venv

# Activate virtual environment

# Windows:

venvScriptsactivate

# macOS/Linux:

source venv/bin/activate

# Install dependencies

pip install -r requirements.txt

# Run the application

python [main.py](http://main.py)

```

### Requirements.txt

```

tkinter-extra==1.0.0

requests>=2.28.0

cryptography>=3.4.8

matplotlib>=3.5.0

reportlab>=3.6.0

beautifulsoup4>=4.11.0

netifaces>=0.11.0

python-nmap>=0.7.1

scapy>=2.4.5

```

## 🚀 Usage Examples

### Quick Network Scan

```

from core.scanner import NetworkScanner

scanner = NetworkScanner()

results = scanner.scan_network('192.168.1.0/24')

print(f"Found {len(results)} active hosts")

```

### Port Scanning

```

from core.port_scanner import PortScanner

port_scanner = PortScanner()

open_ports = port_scanner.scan_host('192.168.1.1', [80, 443, 22, 21])

print(f"Open ports: {open_ports}")

```

### SSL Analysis

```

from core.ssl_analyzer import SSLAnalyzer

ssl_analyzer = SSLAnalyzer()

ssl_info = ssl_analyzer.analyze_certificate('[example.com](http://example.com)', 443)

print(f"Certificate expires: {ssl_info['expiration_date']}")

```

### GUI Application

```

# Launch the GUI application

python [main.py](http://main.py)

# Or run specific modules

python -m core.scanner --target 192.168.1.0/24

python -m core.ssl_analyzer --host [example.com](http://example.com) --port 443

```

## 📋 Feature Roadmap

### Version 1.0 (Current)
- ✅ Basic port scanning
- ✅ Network discovery
- ✅ Simple GUI interface
- ✅ Basic reporting

### Version 2.0 (In Progress)
- 🔄 Advanced vulnerability detection
- 🔄 SSL/TLS deep analysis
- 🔄 Network topology mapping
- 🔄 Export to multiple formats

### Version 3.0 (Planned)
- 📅 Web interface
- 📅 REST API
- 📅 Plugin system
- 📅 Advanced analytics

## 🎯 Professional Benefits

### For Portfolio
- **Real-world Application** - Solves actual security problems
- **Clean Code Architecture** - Well-structured and documented code
- **Modern Technologies** - Uses current Python libraries and practices
- **Professional Documentation** - Complete README and documentation

### For Job Applications
- **Cybersecurity Skills** - Demonstrates practical security knowledge
- **Python Proficiency** - Shows advanced Python programming skills
- **GUI Development** - Interface development capabilities
- **Problem Solving** - Creative solutions to complex problems

## 🧪 Testing

```

# Run all tests

python -m pytest tests/

# Run specific test modules

python -m pytest tests/test_[scanner.py](http://scanner.py)

python -m pytest tests/test_network_[discovery.py](http://discovery.py)

# Run tests with coverage

python -m pytest --cov=core tests/

```

## 📚 Documentation

- [Installation Guide](docs/[installation.md](http://installation.md))
- [Usage Documentation](docs/[usage.md](http://usage.md))
- [API Reference](docs/api_[reference.md](http://reference.md))

## 🔒 Ethical Usage

> ⚠️ **IMPORTANT**: This tool is created for educational purposes and ethical testing only. Use only on your own networks or with explicit written permission. Respect local and international laws regarding network security testing.

### Legal Disclaimer

- Only use on networks you own or have explicit permission to test
- Comply with all applicable laws and regulations
- Do not use for malicious purposes
- Respect system resources and network performance

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```

# Install development dependencies

pip install -r requirements-dev.txt

# Run code formatting

black .

# Run linting

flake8 .

# Run type checking

mypy core/

```

## 📞 Support

- **GitHub Issues** - Report bugs and request features
- **Email** - Contact for professional inquiries
- **Documentation** - Check our comprehensive docs

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Alen Pepa**
- GitHub: [@alenpepa](https://github.com/alenpepa)
- Email: [xalenpepa2@gmail.com](mailto:xalenpepa2@gmail.com)
- LinkedIn: [Alen Pepa](https://linkedin.com/in/alenpepa)

## 🙏 Acknowledgments

- Python community for excellent libraries
- Cybersecurity community for best practices
- Open source contributors

---

**Status:** Active Development 🚀 | **Version:** 1.0.0 | **Last Updated:** August 2025

```

