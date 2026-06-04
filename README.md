# GuardScanner V2

GuardScanner V2 is a modular web security assessment framework developed in Python for educational and authorized security testing purposes.

The project was designed to automate website reconnaissance, crawling, and basic vulnerability assessment while providing a structured and extensible architecture for security analysis.

---

## Overview

GuardScanner V2 helps security enthusiasts and developers understand common web application security issues by performing automated scans against authorized targets.

The framework combines multiple security modules into a single workflow, enabling reconnaissance, crawling, and vulnerability discovery.

---

## Features

### Website Crawling

- Discover website pages
- Extract internal links
- Map website structure

### Reconnaissance

- Target information gathering
- Header analysis
- Technology fingerprinting

### Security Assessment

- SQL Injection Checks
- Cross-Site Scripting (XSS) Detection
- Security Header Analysis
- Input Validation Testing

### Reporting

- Scan Results Summary
- Vulnerability Findings
- Structured Output Reports

---

## Tech Stack

- Python
- Requests
- BeautifulSoup
- HTML Parsing
- Regular Expressions
- HTTP Protocol Analysis

---

## Architecture

Target URL
     ↓
Crawler Module
     ↓
Reconnaissance Module
     ↓
Vulnerability Scanner
     ↓
Report Generator

Each module is designed independently to improve maintainability and allow future feature expansion.

---

## Project Structure

GuardScannerV2/
├── crawler/
├── scanner/
├── recon/
├── reporting/
├── utils/
├── wordlists/
└── main.py

---

## Example Workflow

1. Enter Target URL
2. Crawl Website Pages
3. Gather Website Information
4. Run Security Checks
5. Generate Scan Results

---

## Challenges Faced

One of the biggest challenges during development was designing a modular architecture where different scanning components could communicate efficiently while remaining independent.

Additional challenges included:

- Handling different website response behaviors
- Managing HTTP request failures
- Preventing duplicate crawl results
- Structuring scan output into readable reports
- Balancing scan speed and accuracy

Through this project, I gained practical experience with:

- HTTP Protocols
- Web Application Architecture
- Python Automation
- Security Testing Concepts
- Modular Software Design

---

## Future Improvements

- Authentication Testing
- Multi-threaded Scanning
- Advanced SQL Injection Detection
- API Security Assessment
- Export Reports to PDF
- Dashboard Interface

---

## Disclaimer

This project is intended strictly for educational purposes and authorized security testing.

Users must obtain proper authorization before scanning any system or website. Unauthorized testing may violate laws, regulations, or organizational policies.

---

## Author

DragonB0i

GitHub:
https://github.com/DragonB0i
