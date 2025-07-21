# Automate VirusTotal

This project provides a Python script to automate file scanning using the VirusTotal API. You can upload files to VirusTotal for analysis and get back the analysis ID.

## Features

*   Upload files to VirusTotal for scanning.
*   Handles both small and large files (files larger than 32MB are uploaded using a special URL).
*   Error handling for common issues like HTTP errors, file not found, and other exceptions.

## Requirements

*   Python 3.x
*   `requests` library

You can install the required library using pip:

```bash
pip install -r requirements.txt
```

## Installation

1.  **Clone the repository:**

    ```bash
    git clone https://github.com/Supernova70/automate-virustotal.git
    cd automate-virustotal
    ```

2.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

3.  **Set up your API Key:**
    Enter your api key in .env file 
    ```bash
    mv .env.examples .env
    ```
## Usage

1.  **Set the file path:**

    In `virustotal.py`, update the `FILE_PATH` variable to the path of the file you want to scan.

    ```python
    FILE_PATH = "/path/to/your/file.ext"
    ```

2.  **Run the script:**

    ```bash
    python virustotal.py
    ```

    The script will upload the file and print the analysis ID.

## Future Features

This section is reserved for upcoming features and enhancements.

*   **Todo Task Management:**
    *   A feature to manage a list of tasks.
*   **Get Analysis Report:**
    *   Implement a function to retrieve the analysis report using the analysis ID.
*   **Scan URLs:**
    *   Add functionality to scan URLs in addition to files.
*   **Configuration File:**
    *   Move API key and other settings to a separate configuration file (e.g., `config.ini` or `.env`).
*   **Command-line Arguments:**
    *   Allow passing the file path and other options as command-line arguments.
