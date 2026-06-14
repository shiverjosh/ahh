# Malware Checker v3

Plain black-and-white self-hosted malware checker with scan history.

## Features

- Uses official RARLAB unrar for better RAR5 compatibility

- Partial archive extraction still scans successfully extracted files

- Clear all saved scan records from the web UI

- Black page with white text only
- Extracts archives first, then scans extracted files one by one
- Detects `.rar` by original filename and sends it straight to official RARLAB unrar
- Uses 7z first only for non-RAR archives, then falls back to unar
- Supports archive extensions like `.rar`, `.7z`, `.zip`, `.tar`, `.gz`, `.iso`
- Shows terminal output in dropdowns
- Stores previous scan records in SQLite
- Does NOT store uploaded files
- Deletes uploaded and extracted files after scan
- Persistent history using Docker volume `scan-data`

## Run

```bash
docker compose up -d --build
```

Open:

```text
http://localhost:8088
```

## Stored data

Only scan records are stored:

- filename
- size
- scan result
- terminal output
- timestamp
- scan counts

The actual uploaded file and extracted files are deleted after each scan.

## Portainer

Use this folder or Git repo as a Portainer Git stack.

Compose path:

```text
docker-compose.yml
```
