# Malware Checker v10

Plain black-and-white self-hosted malware checker with background scan jobs, upload progress, live scan status, scan history, and shield favicon.

## New in v10

- Upload progress bar with percentage
- Live scan status updates in Previous scans
- Shows queued / extracting / scanning / final result
- Shows SHA256 hash for each uploaded file
- Better black/white buttons
- Roboto Mono font
- Larger text and larger title

## Existing features kept

- Background scan jobs after upload completes
- You can close the page after the upload is queued
- Previous scan records persist in SQLite
- Clear all saved scan records from the web UI
- Uses official RARLAB unrar first for `.rar` files
- Uses 7z / unar for other archive formats
- Partial archive extraction still scans successfully extracted files
- Uploaded files and extracted files are deleted after scanning
- Only scan reports/history are stored
- Shield favicon included

## Important behavior

You must keep the browser tab open while the file is still uploading.

After the upload finishes and the page says the scan is queued, the scan continues on the server in the background. You can close the page and come back later to see the result in Previous scans.

## Run

```bash
docker compose up -d --build
```

Open:

```text
http://localhost:8088
```

## Stored data

The app stores only scan records in `/data/scan_history.sqlite3` inside the Docker volume `scan-data`.

It does not permanently store uploaded files or extracted files.
