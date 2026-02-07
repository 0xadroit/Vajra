# ⚡ Vajra

<div align="center">

```
██╗   ██╗ █████╗      ██╗██████╗  █████╗ 
██║   ██║██╔══██╗     ██║██╔══██╗██╔══██╗
██║   ██║███████║     ██║██████╔╝███████║
╚██╗ ██╔╝██╔══██║██   ██║██╔══██╗██╔══██║
 ╚████╔╝ ██║  ██║╚█████╔╝██║  ██║██║  ██║
  ╚═══╝  ╚═╝  ╚═╝ ╚════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

**AI-Powered Autonomous Security Scanner & Penetration Testing Framework**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.6-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-20+-green.svg)](https://nodejs.org/)

[Features](#-features) • [Installation](#-installation) • [Quick Start](#-quick-start) • [Documentation](#-documentation) • [Architecture](#-architecture)

</div>

---

## 🎯 What is Vajra?

**Vajra** (Sanskrit: वज्र, meaning "thunderbolt" or "diamond") is an AI-powered autonomous security scanner that finds real vulnerabilities in your web applications. Unlike traditional scanners that generate endless false positives, Vajra uses advanced AI to intelligently analyze your application, craft context-aware payloads, and verify exploits.

### Why Vajra?

- **🤖 AI-Powered Analysis**: Uses Claude/GPT to understand your application context and generate intelligent attack strategies
- **🎯 Real Exploits, Not Alerts**: Verifies vulnerabilities with actual proof-of-concept exploits
- **🔍 Deep Code Understanding**: Combines white-box source analysis with black-box dynamic testing
- **📊 Actionable Reports**: Generates detailed reports with remediation guidance and CVSS scores
- **🚀 Fully Autonomous**: Launch a complete pentest with a single command

---

## ✨ Features

### Vulnerability Detection

| Category | Vulnerabilities |
|----------|----------------|
| **Injection** | SQL Injection (Error, Blind, Time-based, Union), Command Injection, XXE |
| **XSS** | Reflected, Stored, DOM-based Cross-Site Scripting |
| **Access Control** | IDOR, Authentication Bypass, Broken Access Control |
| **SSRF** | Server-Side Request Forgery, Cloud Metadata Access |
| **File Inclusion** | Local File Inclusion (LFI), Remote File Inclusion (RFI) |
| **Configuration** | CORS Misconfiguration, Missing Security Headers, SSL/TLS Issues |

### Key Capabilities

- **🌐 Intelligent Crawling**: Discovers endpoints, APIs, and parameters automatically
- **🔐 Authentication Support**: Basic, Bearer, Cookie, OAuth2, and custom login flows
- **🎭 Browser Automation**: Uses Playwright for JavaScript-rendered content and DOM-based testing
- **📈 Technology Detection**: Identifies frameworks, libraries, and server technologies
- **🔄 CI/CD Integration**: SARIF output for GitHub Security, GitLab SAST, and more
- **🐳 Docker Support**: Run scans in isolated containers

---

## 📦 Installation

### Prerequisites

- Node.js 20 or higher
- npm or yarn
- An AI API key (Anthropic Claude or OpenAI)

### NPM Installation

```bash
# Install globally
npm install -g vajra

# Or use npx
npx vajra scan https://example.com
```

### From Source

```bash
# Clone the repository
git clone https://github.com/vajra-security/vajra.git
cd vajra

# Install dependencies
npm install

# Build
npm run build

# Link globally (optional)
npm link
```

### Docker

```bash
# Build the image
docker build -t vajra .

# Run a scan
docker run -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  -v $(pwd)/reports:/app/reports \
  vajra scan https://example.com
```

---

## 🚀 Quick Start

### 1. Set up your API key

```bash
# For Anthropic Claude (recommended)
export ANTHROPIC_API_KEY=your-api-key

# Or for OpenAI
export OPENAI_API_KEY=your-api-key
```

### 2. Run your first scan

```bash
vajra scan https://your-target.com
```

### 3. View the report

Reports are saved to `./vajra-reports/` by default. Open the HTML report in your browser for a detailed view.

---

## 📖 Documentation

### Command Line Interface

```bash
# Basic scan
vajra scan https://example.com

# Scan with specific modules
vajra scan https://example.com -m xss,sqli,ssrf

# Use a configuration file
vajra scan https://example.com -c vajra.config.yaml

# Specify output format and directory
vajra scan https://example.com -f html,json,sarif -o ./reports

# With authentication
vajra scan https://example.com --auth-type bearer --auth-token $TOKEN

# Verbose output
vajra scan https://example.com -v
```

### Available Commands

| Command | Description |
|---------|-------------|
| `vajra scan <url>` | Run a security scan |
| `vajra init` | Create a configuration file |
| `vajra modules` | List available scanning modules |
| `vajra report <file>` | Generate report from scan results |

### Scan Options

| Option | Description | Default |
|--------|-------------|---------|
| `-c, --config <path>` | Configuration file path | - |
| `-m, --modules <list>` | Modules to run (comma-separated) | all |
| `-o, --output <dir>` | Output directory | ./vajra-reports |
| `-f, --format <list>` | Report formats | html,json |
| `--ai-provider` | AI provider (anthropic/openai) | anthropic |
| `--concurrency` | Concurrent requests | 5 |
| `--timeout` | Request timeout (ms) | 30000 |
| `--max-depth` | Maximum crawl depth | 3 |
| `--include-subdomains` | Include subdomains | false |
| `--screenshots` | Include screenshots | false |
| `--poc` | Include proof of concept | true |

### Configuration File

Create a `vajra.config.yaml` file:

```yaml
target:
  url: "https://example.com"
  scope:
    includeSubdomains: false
    followRedirects: true
    respectRobotsTxt: true
  maxDepth: 3
  excludePaths:
    - /logout
    - /admin

ai:
  provider: "anthropic"
  model: "claude-sonnet-4-20250514"
  maxTokens: 4096

scanning:
  modules:
    - reconnaissance
    - xss
    - sqli
    - ssrf
    - auth-bypass
    - idor
    - lfi
    - command-injection
    - cors
    - security-headers
  concurrency: 5
  timeout: 30000
  delayBetweenRequests: 100

reporting:
  format:
    - html
    - json
    - sarif
  outputDir: "./vajra-reports"
  includeScreenshots: true
  includeProofOfConcept: true
  severity:
    - critical
    - high
    - medium

authentication:
  type: bearer
  credentials:
    token: ${AUTH_TOKEN}
```

---

## 🏗 Architecture

Vajra uses a multi-agent architecture inspired by human penetration testing methodology:

```
┌─────────────────────────────────────────────────────────────┐
│                      ORCHESTRATOR                            │
│                  (Coordinates all phases)                    │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ RECONNAISSANCE│    │  VULNERABILITY │    │  EXPLOITATION  │
│    AGENT      │───▶│   ANALYZER     │───▶│    AGENT       │
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ • URL Discovery│   │ • XSS Scanner  │    │ • PoC Generator│
│ • Tech Detection│  │ • SQLi Scanner │    │ • Exploit Code │
│ • Form Analysis│   │ • SSRF Scanner │    │ • Verification │
│ • API Discovery│   │ • Auth Scanner │    │ • Screenshots  │
└───────────────┘    └───────────────┘    └───────────────┘
                              │
                              ▼
                    ┌───────────────┐
                    │   REPORTER    │
                    │               │
                    │ • HTML Report │
                    │ • JSON/SARIF  │
                    │ • Markdown    │
                    └───────────────┘
```

### Phase 1: Reconnaissance

The reconnaissance agent maps the attack surface:
- Crawls the application using browser automation
- Discovers endpoints, parameters, and forms
- Detects technologies and frameworks
- Parses robots.txt and sitemaps
- Identifies authentication mechanisms

### Phase 2: Vulnerability Analysis

Specialized scanners test for different vulnerability types:
- AI generates context-aware payloads
- Tests each parameter with multiple techniques
- Correlates responses to identify vulnerabilities
- Minimizes false positives through intelligent analysis

### Phase 3: Exploitation

The exploitation agent verifies findings:
- Attempts to exploit discovered vulnerabilities
- Generates proof-of-concept code
- Captures screenshots of successful exploits
- Creates reproducible curl commands

### Phase 4: Reporting

The reporter generates comprehensive documentation:
- Executive summary with risk scores
- Detailed vulnerability descriptions
- Remediation recommendations
- CVSS scores and CWE references
- SARIF output for CI/CD integration

---

## 🔒 Security & Ethics

### Authorized Testing Only

⚠️ **Vajra is designed for authorized security testing only.** 

Before using Vajra:
- Ensure you have written authorization to test the target
- Understand and comply with applicable laws and regulations
- Never test systems you don't own or have permission to test

### Responsible Disclosure

If you discover vulnerabilities using Vajra:
1. Report them responsibly to the affected organization
2. Allow reasonable time for remediation
3. Do not exploit vulnerabilities for personal gain

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repo
git clone https://github.com/vajra-security/vajra.git
cd vajra

# Install dependencies
npm install

# Run in development mode
npm run dev

# Run tests
npm test

# Build
npm run build
```

---

## 📄 License

Vajra is released under the [MIT License](LICENSE).

---

## 🙏 Acknowledgments

- Inspired by [Shannon](https://github.com/KeygraphHQ/shannon) by Keygraph
- Built with [Anthropic Claude](https://anthropic.com) and [OpenAI](https://openai.com)
- Uses [Playwright](https://playwright.dev) for browser automation

---

<div align="center">

**Made with ⚡ by the Vajra Security Team**

[Report Bug](https://github.com/vajra-security/vajra/issues) • [Request Feature](https://github.com/vajra-security/vajra/issues) • [Documentation](https://vajra-security.github.io/vajra)

</div>
# vajra
