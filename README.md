## ⚠️ Legal Disclaimer

NetMan is a security testing toolkit built for educational purposes and authorized security testing only.

This project includes tools capable of network scanning, traffic interception, automated exploitation, and post-exploitation activity (including a C2 beacon component). These capabilities are intended strictly for use in environments you own, or environments you have **explicit, documented authorization** to test — such as personal lab setups (DVWA, Juice Shop, TryHackMe, HackTheBox), CTF competitions, or bug bounty programs where the scope explicitly permits the techniques used.

**Do not use this tool against any system without prior mutual consent.** Unauthorized access to computer systems is illegal in most jurisdictions, including under the U.S. Computer Fraud and Abuse Act (CFAA) and equivalent laws elsewhere.

The author(s) of this project are not responsible for any misuse of this software or any damages resulting from its use. By using this software, you agree that you are solely responsible for ensuring your activities are legal and authorized.

If you are unsure whether your intended use is authorized, do not proceed.# NetMan System Architecture Specification

**NetMan** is a comprehensive, multi-threaded network security and traffic analysis suite. Built in Python 3.14 using a Tkinter frontend, it isolates a heavy-duty backend engine architecture from a responsive graphical interface using asynchronous polling and thread-safe queues. The system integrates traditional penetration testing tools with a local AI/Agent layer for automated traffic analysis and vulnerability discovery.

## 1. Core Orchestration & Infrastructure

The backbone of the application, responsible for routing data, managing state, and rendering the unified interface.

- **Main GUI Orchestrator (`gui_test.py`):** The primary entry point. Initializes the Tkinter `Notebook` (tabbed layout) and seamlessly binds the individual `_gui.py` components into a single window.
- **MITM Proxy (`mitm_proxy.py` & `interceptor_engine.py`):** The inline traffic interception engine. Features on-the-fly TLS certificate forging using a local Root CA, bidirectional WebSocket proxying, and an "Auto-Scope" mechanism to lock onto target domains.
- **State & Data Management (`project_engine.py`, `logger_engine.py`, `reporter_engine.py`):** Handles secure, atomic file operations for saving project states, logging HTTP histories, and generating formatted Markdown/HTML vulnerability reports.
- **IPC Bridge (`local_bridge.py`):** A custom TCP-based socket bridge for inter-process communication and broadcasting structured JSON events.
- **HTTP Utilities (`http_utils.py`):** Centralized normalization for HTTP requests/responses, handling Brotli/Gzip decompression, chunked transfer decoding, and multipart form formatting.

## 2. Artificial Intelligence & Autonomous Agents

The "brain" of the suite, designed to offload analysis to heavy-duty local AI servers or cloud APIs.

- **AI Engine (`ai_engine.py` / `ai_gui.py`):** Manages API connections and prompt execution for security analysis.
- **Agent Engine (`agent_engine.py`):** An autonomous reasoning layer that consumes raw proxy events, maintains long-running memory context, and dispatches structured analysis tasks to the AI Engine to detect complex vulnerabilities without human intervention.

## 3. Reconnaissance & Surface Mapping

Tools dedicated to enumerating the target's infrastructure and attack surface.

- **Port Scanner (`scanner_engine.py`):** A high-performance, `asyncio`-driven TCP port scanner with service banner grabbing.
- **Subdomain Enumerator (`subdomain_engine.py` / `gui`):** A multi-threaded DNS resolver for discovering hidden infrastructure using custom or built-in wordlists.
- **Technology Fingerprinting (`tech_engine.py` / `gui`):** Detects backend frameworks, CMS platforms, and security headers, including active probes for `X-Forwarded-For` support.
- **Web Crawler (`crawler_engine.py` / `gui`):** Parses DOM structures to map accessible links, extract JavaScript files, and locate hidden form inputs.
- **Discovery (`discovery_engine.py` / `gui`):** Directory and file brute-forcing to uncover unlinked assets.

## 4. Active Exploitation & Fuzzing

Engines that mutate data and actively attack target endpoints.

- **Intruder (`intruder_engine.py`):** A highly concurrent payload fuzzer supporting Sniper, Pitchfork, and Cluster Bomb attack types. Includes dynamic Macro extraction and `X-Forwarded-For` IP spoofing rotation.
- **Repeater (`repeater_engine.py`):** Allows manual manipulation and replaying of intercepted HTTP requests with automatic `Content-Length` calculation and CRLF normalization.
- **Vulnerability Scanners (`xss_engine.py`, `idor_engine.py`):** Automated payload injection modules. The XSS engine uses unique randomized trackers to verify reflection, while the IDOR engine iterates through object IDs using captured auth headers.
- **API Analyzer (`api_engine.py` / `gui`):** Specialized testing for REST/GraphQL endpoint misconfigurations.

## 5. Authentication, Cryptography & Token Analysis

Modules for breaking, forging, and analyzing access controls.

- **JWT Tamperer (`jwt_engine.py` / `gui`):** Decodes JSON Web Tokens and allows manual payload/header modification and reconstruction.
- **Authentication Tester (`auth_engine.py` / `gui`):** Dedicated engine for testing login mechanisms and session handling.
- **Decoder & Cracker (`decoder_engine.py`, `cracker_engine.py`):** Utilities for multi-format encoding/decoding (Base64, URL, HTML) and cryptographic hash cracking.
- **MFA Utilities (`generate_mfa.py`):** Specialized tools for interacting with Multi-Factor Authentication token generation.

## 6. Passive Analysis & Compliance

Engines that observe traffic and configurations without sending malicious payloads.

- **Passive Skimmer (`skimmer_engine.py`):** Applies dense Regex rulesets across all proxy traffic to silently catch leaked AWS keys, internal IPs, SSRF parameters, and leaked credentials in real-time.
- **SSL/TLS Analyzer (`ssl_engine.py` / `gui`):** Deep-packet inspection of transport security, flagging expired certificates, weak cipher suites, and deprecated TLS 1.0/1.1 protocols.
- **Dependency Scanner (`vuln_engine.py` / `gui`):** Parses `package-lock.json` and similar lockfiles, querying the `api.osv.dev` database to flag known CVEs in frontend/backend dependencies.
- **Compliance Validator (`compliance_engine.py` / `gui`):** Maps discovered vulnerabilities to specific regulatory and industry compliance frameworks (e.g., OWASP, PCI-DSS).
