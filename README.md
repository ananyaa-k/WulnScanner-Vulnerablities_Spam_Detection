# Wulnscan 🛡️

**Multi-Functional Security Scanner & NLP Threat Classifier**

Wulnscan is an automated security pipeline built in Python that consolidates network reconnaissance, web vulnerability assessment, and AI-driven threat classification into a single cohesive tool. It is designed to streamline routine penetration testing workflows and reduce manual enumeration time.

## ✨ Features

* **Network Reconnaissance:** Integrates `Nmap` for automated port scanning, service enumeration, and network discovery.
* **Web Vulnerability Assessment:** Actively analyzes target URLs to identify critical web vulnerabilities, including:
    * SQL Injection (SQLi)
    * Cross-Site Scripting (XSS)
* **NLP Threat Classification:** Leverages Natural Language Processing (NLP) and a Naive Bayes machine learning algorithm to accurately detect, classify, and filter malicious payloads and spam communications.
* **Unified Pipeline:** Consolidates multiple security assessment phases (reconnaissance, scanning, and payload analysis) into one executable workflow.

## 🛠️ Technology Stack

* **Language:** Python 3.x
* **Network Scanning:** Nmap, `python-nmap`
* **Machine Learning / NLP:** `scikit-learn`, Natural Language Toolkit (NLTK)
* **Web Requests:** `requests`, `BeautifulSoup`

## ⚙️ Prerequisites

Before running Wulnscan, ensure you have the following installed on your system:

1.  **Python 3.8+**
2.  **Nmap:** Wulnscan relies on the underlying Nmap utility. 
    * *Debian/Kali:* `sudo apt-get install nmap`
    * *macOS:* `brew install nmap`
    * *Windows:* Download from the [official Nmap website](https://nmap.org/download.html).

## 🚀 Installation

1. Clone the repository:
   git clone [https://github.com/ananyaa-k/wulnscan.git](https://github.com/ananyaa-k/wulnscan.git)
   cd wulnscan

 2. (Optional but recommended) Create a virtual environment:
  python -m venv venv
  source venv/bin/activate  # On Windows use: venv\Scripts\activate
  
 3. Install the required Python dependencies:
    pip install -r requirements.txt

💻 Usage
(Note: Update the command-line arguments below to match your actual script implementation)

> Run the Wulnscan main script and provide a target IP or URL.
Basic Network Scan:
python wulnscan.py --target 192.168.1.1 --scan network
> Web Vulnerability Scan (SQLi/XSS):
python wulnscan.py --url [http://example.com/login](http://example.com/login) --scan web
> Analyze Payload/Text using NLP Classifier:
python wulnscan.py --text "your_suspicious_payload_here" --analyze


🔮 Roadmap: Autonomous AI Agent Integration
 The future vision for Wulnscan is to evolve from a multi-functional scanner into a stateful, AI-driven penetration testing agent. Planned features include:
 - LLM-Driven Orchestration: Implementing an autonomous reasoning loop (e.g., utilizing LangGraph) that allows Wulnscan to ingest initial reconnaissance and dynamically determine the next logical testing phase without human intervention.
 - Privacy-First Local AI: Integrating support for self-hosted, open-source LLMs (such as Ollama) to process sensitive scan data and generate payloads entirely locally, ensuring strict operational security and data privacy.
 - Contextual Payload Synthesis: Upgrading the web assessment module so the AI agent can intelligently craft context-aware SQLi and XSS payloads tailored to the specific server responses and parameters discovered.
 - Stateful Attack Graphing: Providing the agent with short-term memory to map out complex attack paths, allowing it to correlate a vulnerability found on one port with an entry point on another.
 - Automated Remediation Reporting: Leveraging generative AI to autonomously translate raw scan outputs into executive-ready penetration test reports complete with actionable mitigation strategies.

⚠️ Disclaimer
Educational and Authorized Use Only. Wulnscan is developed for educational purposes, security research, and authorized penetration testing. The author is not responsible for any misuse, damage, or illegal activities conducted with this tool. Always ensure you have explicit, written permission from the system owner before scanning or testing any network or web application.

🤝 Contributing
Contributions, issues, and feature requests are welcome! Feel free to check the issues page if you want to contribute.
