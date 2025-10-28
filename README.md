# OSINT CLI Tool

A comprehensive command-line OSINT (Open Source Intelligence) tool for information gathering and reconnaissance.

## Features

- **Email Investigation**: Email validation, breach checking, and social media lookup
- **Domain Analysis**: WHOIS lookup, DNS records, subdomain enumeration
- **IP Address Investigation**: Geolocation, ISP information, port scanning
- **Social Media Intelligence**: Username availability across platforms
- **Data Breach Checking**: Check if emails have been compromised
- **Report Generation**: Clean, formatted output for analysis

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/osint-cli.git
cd osint-cli
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Install the tool:
```bash
pip install -e .
```

## Usage

### Basic Usage
```bash
osint-cli --help
```

### Email Investigation
```bash
osint-cli email --target user@example.com
```

### Domain Analysis
```bash
osint-cli domain --target example.com
```

### IP Investigation
```bash
osint-cli ip --target 8.8.8.8
```

### Social Media Lookup
```bash
osint-cli social --username john_doe
```

### Comprehensive Scan
```bash
osint-cli scan --target example.com --type all
```

## Requirements

- Python 3.8+
- Internet connection
- Valid API keys for enhanced features (optional)

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations.