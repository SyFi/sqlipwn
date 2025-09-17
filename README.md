# SQLiPwn - Professional SQL injection detection and exploitation tool


<p align="center">
  <img src="https://img.shields.io/badge/Version-2.1-brightgreen.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.7%2B-blue.svg" alt="Python Version">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey.svg" alt="Platform">
</p>

<p align="center">
  <strong>Professional-grade SQL injection detection and exploitation tool</strong><br>
  Multi-threading | Authentication Support | Professional Reports | WAF Evasion
</p>

---
<img width="2984" height="1684" alt="image" src="https://github.com/user-attachments/assets/e46f8b96-bc71-4036-88f7-a5b69c77b33f" />

**Report**

<img width="2420" height="1516" alt="image" src="https://github.com/user-attachments/assets/03213582-58f2-45cd-986b-8ac763534217" />

## 🚀 Features

### Core Capabilities
- **Advanced SQL Injection Detection** - Error-based, Boolean blind, Time-based, Union-based
- **Multi-threaded Scanning** - Configurable thread pools for optimal performance
- **Intelligent Web Crawling** - Automated parameter discovery with smart link prioritization
- **Authentication Support** - Session cookies, custom headers, and auth testing
- **Professional Reporting** - Interactive HTML dashboards and JSON exports

### Security Features
- **WAF Evasion Techniques** - Advanced payload encoding and obfuscation
- **User Agent Rotation** - Randomized user agents for stealth scanning
- **Proxy Support** - Burp Suite integration and custom proxy routing
- **False Positive Reduction** - Advanced validation algorithms

### Scan Modes
- **Fast Mode** - Optimized payloads for time-critical assessments
- **Standard Mode** - Balanced approach for comprehensive coverage
- **Thorough Mode** - Extended payloads with advanced evasion techniques

## 📦 Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Quick Install
```bash
# Clone the repository
git clone https://github.com/syfi/sqlipwn.git
cd sqlipwn

# Install dependencies
pip install -r requirements.txt

# Run SQLiPwn
python sqlipwn.py -u https://example.com
```

### Manual Installation
```bash
pip install requests beautifulsoup4 colorama lxml
```

## 🎯 Quick Start

### Basic Scan
```bash
python sqlipwn.py -u https://example.com
```

### Authenticated Scan with Session Cookies
```bash
python sqlipwn.py -u https://app.example.com --cookies "session=abc123; token=xyz789"
```

### Fast Scan for Time-Critical Testing
```bash
python sqlipwn.py -u https://example.com --fast
```

### Comprehensive Scan with WAF Evasion
```bash
python sqlipwn.py -u https://example.com --thorough --random-user-agent
```

## 📖 Usage Guide

### Command Line Options

#### Essential Parameters
```bash
-u, --url           Target URL to scan (required)
-d, --depth         Maximum crawl depth (default: 3)
-t, --threads       Number of concurrent threads (default: 10)
--delay             Delay between requests in seconds (default: 0.5)
--timeout           HTTP request timeout (default: 10)
```

#### Authentication Options
```bash
--cookies           Session cookies ("name1=value1; name2=value2")
--cookie-file       Path to cookie file (JSON/Netscape/simple format)
--headers           Custom HTTP headers ("Header1: Value1; Header2: Value2")
--auth-test         Test authentication before scanning
```

#### Scan Modes
```bash
--fast              Fast scan mode (reduced payloads)
--thorough          Thorough scan mode (extended payloads + WAF evasion)
```

#### Evasion & Proxy
```bash
--random-user-agent Use random user agent rotation
--proxy             HTTP proxy URL (e.g., http://127.0.0.1:8080)
```

### Advanced Examples

#### API Testing with Authentication Headers
```bash
python sqlipwn.py -u https://api.example.com \
  --headers "Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..." \
  --depth 2 --threads 5
```

#### Deep Crawl with Burp Suite Integration
```bash
python sqlipwn.py -u https://example.com \
  --depth 5 \
  --proxy http://127.0.0.1:8080 \
  --random-user-agent \
  --thorough
```

#### Cookie File Authentication
```bash
# Export cookies from browser to cookies.json
python sqlipwn.py -u https://app.example.com \
  --cookie-file cookies.json \
  --auth-test
```

## 📊 Report Generation

SQLiPwn automatically generates comprehensive reports:

### HTML Dashboard
- **Interactive vulnerability cards** with detailed information
- **SQLMap integration commands** ready for exploitation
- **Professional styling** with responsive design
- **Copy-to-clipboard functionality** for commands

### JSON Export
- **Machine-readable format** for integration with other tools
- **Detailed scan metadata** and vulnerability information
- **Perfect for CI/CD pipelines** and automated workflows

### Sample Report Structure
```
sqlipwn_report_example_com_20241215_143022.html
├── Scan Summary (vulnerabilities by risk level)
├── Vulnerability Details
│   ├── Error-based SQL Injection
│   ├── Boolean-based Blind SQL Injection
│   ├── Time-based Blind SQL Injection
│   └── Union-based SQL Injection
└── SQLMap Commands (ready for exploitation)
```

## 🔧 Configuration

### Cookie File Formats

#### JSON Format (Chrome/Firefox Export)
```json
[
  {
    "name": "session_id",
    "value": "abc123xyz",
    "domain": ".example.com",
    "path": "/"
  }
]
```

#### Simple Format
```
session_id=abc123xyz
auth_token=def456uvw
```

#### Netscape Format
```
.example.com	TRUE	/	FALSE	1640995200	session_id	abc123xyz
```

### Custom Headers Example
```bash
--headers "Authorization: Bearer token123; X-API-Key: key456; Content-Type: application/json"
```

## 🎨 Scan Modes Comparison

| Feature | Fast Mode | Standard Mode | Thorough Mode |
|---------|-----------|---------------|---------------|
| Payloads | ~40 optimized | ~80 comprehensive | ~120+ with evasion |
| Speed | Fastest | Balanced | Comprehensive |
| Detection Rate | High confidence only | Balanced | Maximum coverage |
| WAF Evasion | Basic | Standard | Advanced |
| Recommended For | Time-limited scans | General testing | Comprehensive audits |

## 🚨 Legal Disclaimer

**IMPORTANT**: This tool is designed for authorized security testing only.

### Authorized Use Only
- **Penetration Testing** with proper authorization
- **Bug Bounty Programs** within scope
- **Security Research** on owned systems
- **Educational Purposes** in controlled environments

### Prohibited Activities
- Testing systems without explicit permission
- Unauthorized access attempts
- Malicious exploitation of vulnerabilities
- Any illegal or unethical activities

### User Responsibility
Users are solely responsible for ensuring they have proper authorization before using this tool. The authors assume no liability for misuse or damage caused by unauthorized usage.

## 🤝 Contributing

### Areas for Contribution
- New injection detection techniques
- Additional database support
- WAF evasion methods
- Report improvements
- Documentation enhancements

## 🐛 Bug Reports & Feature Requests

### Reporting Issues
- Use the GitHub Issues tracker
- Include detailed reproduction steps
- Provide sample URLs (if safe to share)
- Include error messages and logs

### Feature Requests
- Describe the use case
- Explain the expected behavior
- Consider implementation complexity

## 📚 Documentation

### Additional Resources
- [SQLMap Documentation](http://sqlmap.org/)
- [OWASP SQL Injection Guide](https://owasp.org/www-community/attacks/SQL_Injection)
- [Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Technical Details
- **Supported Databases**: MySQL, PostgreSQL, Oracle, SQL Server, SQLite
- **Injection Types**: Error-based, Boolean blind, Time-based, Union-based
- **Authentication**: Session cookies, API keys, custom headers
- **Output Formats**: HTML dashboard, JSON export

## 📈 Performance Tips

### Optimization Guidelines
- **Thread Count**: Start with 10-20 threads, adjust based on target capacity
- **Request Delay**: Use 0.2-1.0 seconds depending on target sensitivity  
- **Timeout Settings**: 10-15 seconds for most targets
- **Crawl Depth**: Limit to 3-5 for large applications

### Best Practices
- Always test authentication before full scans
- Use proxy for debugging and traffic analysis
- Start with fast mode, then thorough if needed
- Monitor target server response times

## 🏆 Credits

**Created by**: syfi


## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔗 Links

- **Documentation**: [Wiki](https://github.com/syfi/sqlipwn/wiki)
- **Bug Reports**: [Issues](https://github.com/syfi/sqlipwn/issues)
- **Feature Requests**: [Discussions](https://github.com/syfi/sqlipwn/discussions)

---

<p align="center">
  <strong>SQLiPwn by syfi</strong><br>
  Professional SQL injection testing for authorized security assessments
</p>
