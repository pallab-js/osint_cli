# OSINT CLI Tool

A comprehensive command-line OSINT (Open Source Intelligence) tool for information gathering and reconnaissance. It supports both online and offline modes, a powerful offline analysis engine, and a smooth, configurable user experience.

## Features

- **Online + Offline**: Run fully offline using local intelligence databases and pattern recognition, or online for live lookups
- **Email Intelligence**: Validation, provider reputation, pattern/risk analysis, optional breach checks
- **Domain Intelligence**: TLD/subdomain risk, structure analysis, optional WHOIS/DNS/SSL live checks
- **IP Intelligence**: Classification (private/reserved/public), basic geodata (offline), live enrichment (optional)
- **Social Intelligence**: Offline username analysis; optional public profile checks
- **Correlation Engine**: Multi-target correlation and risk summaries (offline)
- **Reporting**: Clean table output; JSON/TXT/HTML in offline engine
- **Configurable UX**: User config for defaults and feature toggles

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

### Email Investigation (online default)
```bash
osint-cli email --target user@example.com
```

### Domain Analysis (online default)
```bash
osint-cli domain --target example.com
```

### IP Investigation (online default)
```bash
osint-cli ip --target 8.8.8.8
```

### Social Media Lookup (online default)
```bash
osint-cli social --username john_doe
```

### Comprehensive Scan
```bash
osint-cli scan --target example.com --type all
```

### Offline Mode

The tool includes a full offline CLI with local intelligence databases and pattern recognition:

```bash
# Email (offline engine)
osint-cli offline email --target user@example.com

# Domain (offline engine)
osint-cli offline domain --target example.com

# Username
osint-cli offline username --target john_doe

# IP
osint-cli offline ip --target 8.8.8.8

# Correlate multiple targets
osint-cli offline correlate --targets user@example.com,example.com,john_doe
```

You can also force offline mode on standard commands using `--offline` (or `--online` to force live lookups when available):

```bash
osint-cli email --target user@example.com --offline
osint-cli domain --target example.com --offline
osint-cli ip --target 8.8.8.8 --offline
osint-cli social --username john_doe --offline
```

### Configuration

Initialize and view configuration (stored at `~/.osint_cli/config.json`):

```bash
# Initialize default config
osint-cli config --init

# Show effective config
osint-cli config --show
```

Key settings include:
- `preferences.prefer_offline`: Default to offline routing when no flags are used
- `network.timeout_seconds`, `network.max_concurrency`, `network.rate_limit_per_sec`
- Feature flags (whois/dns/ssl/social/breach/tor) for future online modules

## Requirements

- Python 3.8+
- Internet connection (for online enrichments only)
- Valid API keys for enhanced features (optional)

## Tests & Coverage

The project includes an extensive test suite (unit + integration) with 100% coverage enforced via `pytest.ini`.

Run tests:

```bash
pytest -q
```

## License

MIT License - see LICENSE file for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## Disclaimer

This tool is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and regulations.