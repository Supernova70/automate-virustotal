# VirusTotal Automated Scanner

A Python tool to automate file scanning and reporting using the VirusTotal API.  
It supports file uploads, hash-based lookups, status checks, and pretty-printed scan reports.

---

## Features

- **Upload files** to VirusTotal for malware analysis (supports files >32MB).
- **Check analysis status** and retrieve detailed scan reports.
- **Hash-based lookup** (SHA256) to avoid re-uploading known files.
- **Pretty-print scan results** for easy reading.
- **Environment variable configuration** for API key and file path.
- **Graceful error handling** for network and file issues.
- **Interactive file path prompt** if the path is missing or invalid.

---

## Usage

1. **Install dependencies:**
   ```bash
   pip install requests python-dotenv
   ```

2. **Set up your `.env` file:**
   ```
   API_KEY=your_virustotal_api_key
   FILE_PATH=/path/to/your/file.exe
   ```

3. **Run the scanner:**
   ```bash
   python virustotal.py
   ```

   - If the file is already in VirusTotal, you'll get a pretty-printed report.
   - If not, the file is uploaded and scanned, and you can check its status.
   - If the file path is missing or invalid, you'll be prompted to enter a valid path.

---

## Example Output

```
API key loaded d841....de2d
This file is already in Virustotal Database

=== File Information ===
Name: myfile.exe
SHA256: ...
MD5: ...
Type: ...
Size: ...

=== Detection Stats ===
Malicious: 0
Suspicious: 0
Undetected: 65
...

=== Major Engine Results ===
Kaspersky: undetected (Clean)
BitDefender: undetected (Clean)
...

=== All Detections ===
No malicious detections found.

=== Scan Date ===
2025-07-21 12:30:35
```

---

## Project Structure

- `virustotal.py` : Main scanner class and CLI logic.
- `.env` : API key and file path configuration.

---

## TODO / Future Scope

- [ ] Add a command-line interface (CLI) with `argparse` for flexible usage.
- [ ] Support batch scanning of multiple files or folders.
- [ ] Export scan reports to HTML, PDF, or Markdown.
- [ ] Integrate notifications (Slack, Discord, email) for scan results.
- [ ] Build a simple GUI (Tkinter, Flask, or Streamlit).
- [ ] Add unit tests and set up CI/CD (GitHub Actions).
- [ ] Dockerize the project for easy deployment.
- [ ] Improve documentation and add usage screenshots.
- [ ] Add threat intelligence enrichment (MITRE ATT&CK, etc.).
- [ ] Create a statistics dashboard (top threats, engine reliability).
- [ ] Handle API rate limits and quotas more robustly.
- [ ] Mask API keys in logs and outputs for security.
- [ ] Schedule automatic re-scans for files.
- [ ] Support multiple API keys and automatic rotation.
- [ ] Add advanced error handling and retry logic for uploads and queries.

---
