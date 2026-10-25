# Sentinel — File Integrity Monitor

A simple Python cybersecurity project that monitors files and detects changes using SHA-256 cryptographic hashes.

Sentinel provides a graphical desktop interface for creating a file baseline, monitoring a selected folder, identifying changes, and exporting scan reports.

> **Project level:** Beginner / learning project  
> **Purpose:** Cybersecurity education and portfolio demonstration  
> **Platform:** Windows desktop

## Features

- **SHA-256 hashing:** Calculates a cryptographic hash for each accessible file.
- **Baseline creation:** Records the initial hashes of files in a selected folder.
- **Change detection:** Identifies added, modified, and deleted files.
- **Real-time monitoring:** Uses Watchdog to observe filesystem activity.
- **Security dashboard:** Displays file counts, detected changes, and recent events.
- **Event investigation:** Shows previous and current SHA-256 hashes for individual events.
- **Windows notifications:** Provides desktop alerts when changes are detected, when notification support is available.
- **Scan summaries:** Records scan times, durations, errors, and skipped items.
- **CSV reports:** Exports scan summaries and security events for further review.

## Technologies Used

- Python
- Tkinter — graphical user interface
- SHA-256 via Python's `hashlib`
- Watchdog — filesystem event monitoring
- Winotify — Windows desktop notifications
- JSON — local baseline and scan-history storage
- CSV — report export

## How It Works

1. Select a folder to monitor.
2. Create a baseline, which calculates and stores the SHA-256 hashes of accessible files.
3. Start monitoring to observe filesystem activity.
4. Add, modify, or delete files in the selected folder.
5. Review detected events in the dashboard.
6. Run a manual scan to compare the current files against the previous known state.
7. Export a CSV report for review.

A file's SHA-256 hash acts as a digital fingerprint of its contents. When the contents change, the hash will normally change as well. Sentinel uses this comparison to help identify unexpected file modifications.

## Installation

### Requirements

- Windows
- Python 3 installed
- Internet access for installing dependencies

### Setup

1. Download or clone this repository.
2. Open a terminal in the project folder.
3. Install the dependencies:

   ```bash
   py -m pip install -r requirements.txt
   ```

4. Launch the application by double-clicking `app.pyw`.

   Alternatively, run it from the terminal:

   ```bash
   py app.pyw
   ```

If the `py` command is unavailable, use your Python installation's equivalent command.

## Testing the Application

For a safe demonstration, create a separate folder containing sample text files.

1. Select the test folder in Sentinel.
2. Click **Create Baseline**.
3. Click **Start Monitoring**.
4. Create a new text file and confirm it is reported as added.
5. Edit an existing file and confirm it is reported as modified.
6. Delete a test file and confirm it is reported as deleted.
7. Use **Scan Now** to reconcile the current folder state.
8. Export a CSV report to inspect the results.

Use disposable test files rather than important system files or sensitive folders.

## Real-World Relevance

File integrity monitoring is relevant to defensive security because unexpected file changes can be an indicator worth investigating.

Related uses include:

- Monitoring configuration files on servers.
- Checking important application files for unexpected changes.
- Identifying changes to security-sensitive scripts.
- Supporting change-control and security-audit processes.
- Helping investigate suspicious modifications to files.

In professional environments, file integrity monitoring is commonly part of a broader security monitoring approach. Sentinel demonstrates the basic concept; it does not replace enterprise endpoint detection, centralized monitoring, or a full security information and event management (SIEM) platform.

## Limitations

- This is a simple educational prototype, not a production-grade security product.
- Real-time filesystem events may be duplicated or missed; manual scans help reconcile the folder state.
- Changes are detected through file contents and observed filesystem events, not by determining whether an action was malicious.
- Files that cannot be accessed may not be included in a scan.
- The application does not currently provide a complete, persistent history of every individual security event across application restarts.
- Windows notifications depend on the relevant dependency and operating-system notification settings.
- The tool does not upload monitored file contents to a remote security service.

## Future Improvements

Possible extensions include persistent event history, scheduled scans, configurable exclusions, improved handling of filesystem errors, and stronger alerting and reporting.

## Disclaimer

This project is intended for educational and defensive security purposes. Test it with files and folders you own or are authorized to monitor.
