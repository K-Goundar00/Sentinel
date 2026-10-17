# Sentinel — File Integrity Monitoring Tool

A Python-based cybersecurity application that monitors file integrity using SHA-256 cryptographic hashing. Sentinel establishes a baseline of files in a selected directory and identifies files that have been added, modified, or deleted.

## Overview

File integrity monitoring is an important security practice used to identify unauthorised or unexpected changes to files. Sentinel demonstrates this concept through a simple desktop application with a graphical user interface (GUI).

The application compares the current state of a monitored folder against a saved baseline and displays detected changes in a security events dashboard.

## Features

- **SHA-256 Hashing:** Generates cryptographic hashes to establish file integrity baselines.
- **File Change Detection:** Identifies added, modified, and deleted files by comparing scans against the saved baseline.
- **Graphical User Interface:** Provides a desktop dashboard built with Python and Tkinter.
- **Security Event Dashboard:** Displays detected changes, timestamps, event types, and file details.
- **CSV Report Export:** Exports detected security events for documentation and further analysis.
- **Local Processing:** Scans files locally without uploading their contents to an external service.

## Technologies Used

- Python
- Tkinter — graphical user interface
- hashlib — SHA-256 hashing
- JSON — baseline storage
- CSV — security report generation
- pathlib and os — filesystem operations

## How It Works

1. **Select a folder:** Choose the directory you want to monitor.
2. **Create a baseline:** Sentinel calculates the SHA-256 hash of each accessible file and saves the results.
3. **Scan for changes:** The application calculates current hashes and compares them against the saved baseline.
4. **Review security events:** Changes are classified as added, modified, or deleted files.
5. **Export a report:** Save detected events as a CSV file for further review.

### Detection Logic

| Event | Detection method |
|---|---|
| Added | File exists in the current scan but not in the baseline |
| Modified | File exists in both scans, but its SHA-256 hash differs |
| Deleted | File exists in the baseline but not in the current scan |

## Getting Started

### Prerequisites

- Windows computer
- Python 3 installed
- Visual Studio Code (recommended for development)

Tkinter is included with most standard Windows Python installations. No additional third-party Python packages are required for the current version.

### Run the Application

1. Clone this repository or download the project files.
2. Open the project folder in Visual Studio Code.
3. Open `app.pyw`.
4. Run the application using your configured Python environment.

The application opens a desktop window for selecting folders, creating baselines, scanning for changes, and exporting reports.

### Test the Application

Use a dedicated test folder containing sample text files.

1. Create a file named `example.txt`.
2. Select the folder in Sentinel and click **Create Baseline**.
3. Modify `example.txt`, save it, and scan again to test modification detection.
4. Create another file and scan to test addition detection.
5. Delete a file that existed when the baseline was created, then scan again to test deletion detection.
6. Export the detected events to a CSV report.

## Project Structure

```text
File-Integrity-Monitor/
├── app.pyw
└── README.md
```

The application stores its baseline and exported reports in a local application-data folder under the user's home directory.

## Security Considerations and Limitations

- The current version detects changes when a scan is initiated manually; continuous real-time monitoring is not implemented.
- File changes are compared against the saved baseline, not the previous scan.
- The baseline should be protected against unauthorised modification. If an attacker can modify the baseline, detection reliability may be compromised.
- Files that cannot be accessed or read may not be included reliably in scan results.
- Sentinel is a learning and portfolio project and is not a replacement for enterprise file integrity monitoring or endpoint detection and response solutions.

## Future Improvements

- Real-time filesystem monitoring
- Persistent security event history
- Baseline integrity protection
- Detection of baseline changes
- Filtering and searching security events
- Improved handling of inaccessible files
- Standalone Windows executable packaging

## Learning Objectives

This project explores practical cybersecurity and software development concepts, including:

- Cryptographic hashing and file integrity verification
- Filesystem monitoring and change detection
- Security event reporting
- Python application development
- Basic defensive security tooling

## Disclaimer

Sentinel is intended for educational and defensive cybersecurity purposes. Test the application on folders you own or are authorised to monitor.

## Author

**Kaushik Goundar**


*Built as a hands-on cybersecurity portfolio project to explore file integrity monitoring and defensive security practices.*
