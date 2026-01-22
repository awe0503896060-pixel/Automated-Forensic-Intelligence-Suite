# Automated Forensic Intelligence Suite (AFIS)

**An automated Bash-based framework for rapid Windows forensic triage.**

## 📋 Project Overview
[cite_start]This tool automates the digital forensic process for Windows systems, combining HDD (Hard Drive) and Memory (RAM) analysis into a single execution flow[cite: 3]. [cite_start]It is designed to streamline investigations by automatically handling dependency management, file recovery, and sensitive data extraction[cite: 4].

## 🚀 Core Functions
* **Auto-Setup & Self-Healing:** The script detects missing dependencies and automatically installs tools like Foremost and Bulk Extractor. [cite_start]It includes a self-healing feature that downloads and installs the Volatility standalone binary if not found[cite: 6, 12].
* **Deep Analysis:**
    * [cite_start]**HDD:** Carves deleted files using `foremost` and identifies network packets (PCAP) using `bulk_extractor`[cite: 7, 35].
    * [cite_start]**Memory:** Automates OS profiling, process mapping (`pslist`), and network connection analysis (`netscan`) via Volatility[cite: 7, 51].
* [cite_start]**Intelligence Extraction:** Scans raw binary data for human-readable strings, specifically targeting "low-hanging fruit" like passwords, logins, and executable paths[cite: 44, 45].
* [cite_start]**Unified Reporting:** Aggregates all logs, carved data, and Volatility outputs into a single, timestamped ZIP archive with a chain of custody summary[cite: 55, 56].

## 🛠️ Prerequisites
* **Operating System:** Linux (Debian/Ubuntu/Kali recommended).
* [cite_start]**Permissions:** Script must be run with `root` privileges to ensure raw device access[cite: 11].
* **Dependencies:** The script will attempt to auto-install the following:
    * Volatility (Standalone 2.6)
    * Foremost
    * Bulk Extractor
    * Strings / Grep

## 💻 Usage

1.  **Clone the Repository**
    ```bash
    git clone [https://github.com/YOUR-USERNAME/Automated-Forensic-Intelligence-Suite.git](https://github.com/YOUR-USERNAME/Automated-Forensic-Intelligence-Suite.git)
    cd Automated-Forensic-Intelligence-Suite
    ```

2.  **Make Executable**
    ```bash
    chmod +x auto_forensics.sh
    ```

3.  **Run the Tool**
    ```bash
    sudo ./auto_forensics.sh
    ```

4.  **Follow the Prompts**
    Enter the full path to your forensic image (HDD or Memdump) when requested.

## 📂 Output Structure
[cite_start]The tool generates a directory `Forensic_Report_[TIMESTAMP]` containing[cite: 52]:

* `analysis_log.txt`: Execution log and timestamps.
* `Carved_Data/`:
    * `Foremost/`: Recovered images, documents, etc.
    * [cite_start]`BulkExtractor/`: Extracted PCAP files and network histograms[cite: 41, 42].
* `Extracted_Text/`:
    * `all_strings.txt`: Raw string dump.
    * `sensitive_findings.txt`: Filtered credentials and interesting patterns.
* `Volatility_Output/`:
    * `pslist.txt`, `network.txt`, `hivelist.txt` (Registry hives).

## ⚠️ Disclaimer
This tool is intended for educational purposes and authorized forensic investigations only. Ensure you have proper authorization before analyzing any data.
