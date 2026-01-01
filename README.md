# Thor Scraper: Tor-Based CTI Data Acquisition Tool

![Go Version](https://img.shields.io/badge/Go-1.20%2B-blue)
![Context](https://img.shields.io/badge/Context-Academic%20Research-lightgrey)

**Thor Scraper** is a headless browser automation tool developed to
collect rendered web content from onion services and clearnet sites via
the Tor network.

This project serves as a **Proof of Concept (PoC)** for automated Cyber
Threat Intelligence (CTI) data gathering. Unlike standard HTTP clients,
it uses the **Chrome DevTools Protocol (CDP)** to capture dynamic
JavaScript content, full-page screenshots, and network activity logs for
analysis.

------------------------------------------------------------------------

## 🎯 Project Scope & Capabilities

The tool focuses on **passive reconnaissance** and **data integrity**
for research purposes:

-   **Tor Network Routing:** Routes all traffic through a local SOCKS5
    proxy (`127.0.0.1:9150`) to enable `.onion` site access.
-   **Leak Mitigation:** Disables WebRTC, QUIC, and DNS prefetching *at
    the browser level* to reduce IP leak risks.
-   **Data Integrity (Hashing):** Calculates **SHA-256** hashes for
    downloaded HTML and screenshots to verify data consistency after
    acquisition.
-   **Isolated Sessions:** Uses a fresh browser context per target to
    reduce cross-site state sharing.
-   **Activity Logging:**
    -   **Network Logs:** Captures background HTTP requests (XHR/Fetch)
        to identify external connections.
    -   **Console Logs:** Records client-side JavaScript errors.

------------------------------------------------------------------------

## 📂 Data Structure

``` text
data/
├── scan_summary.json         # Scan report (targets, status, timestamps)
├── example.com/              # Target domain
│   └── 2025-01-01_12-00/     # Timestamped session
│       ├── full_page.png     # Full-page screenshot (Quality: 70)
│       ├── source.html       # Raw DOM content
│       ├── meta.json         # Metadata & SHA-256 hashes
│       └── logs/
│           ├── network.log   # Outgoing HTTP requests
│           ├── console.log   # Browser console output
│           └── error.log     # Runtime errors
```

------------------------------------------------------------------------

## 🛠️ Installation & Usage

### Prerequisites

-   **Go (Golang):** v1.20+
-   **Tor Browser:** Must be running in the background (Default SOCKS5
    port: 9150)

### 1. Setup

``` bash
git clone https://github.com/enstalha/Thor-Scraper.git
cd Thor-Scraper
go mod init thor-scraper
go mod tidy
```

### 2. Configuration

Edit `targets.yaml` to define target URLs:

``` yaml
http://example.onion
https://check.torproject.org
```

### 3. Execution

``` bash
go run main.go
```

> **Note:** The tool performs a pre-flight check to verify Tor
> connectivity before scanning.

------------------------------------------------------------------------

## ⚠️ Disclaimer

This tool is developed for **academic and educational purposes only**.

-   It is designed for **passive data collection** and does not perform
    active scanning or exploitation.
-   While it implements basic leak mitigation (WebRTC/QUIC disabled), it
    does **not** provide the same level of anonymity as the official Tor
    Browser Bundle.
-   The developer is not responsible for any misuse of this software.
