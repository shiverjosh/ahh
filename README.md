# Malware Checker v2

Plain black-and-white self-hosted malware checker.

## What changed

- Black page with white text only
- Extracts archives first, then scans extracted files one by one
- Supports archive extensions like `.rar`, `.7z`, `.zip`, `.tar`, `.gz`, `.iso`
- Shows terminal-style extraction and scan output
- Deletes uploaded and extracted files after scan
- Honest statuses:
  - CLEAN
  - INFECTED
  - SCAN INCOMPLETE
  - SCAN FAILED

## Why extraction mode exists

ClamAV cannot reliably fully scan individual files larger than around 2GB.

For a large RAR/7z/zip, this app extracts the archive first and scans the extracted files individually.

If an extracted file is still over 2GB, the app marks the result as SCAN INCOMPLETE.

## Run

```bash
docker compose up -d --build
```

Open:

```text
http://localhost:8088
```

## Portainer

Use this folder or Git repo as a Portainer Git stack.

Compose path:

```text
docker-compose.yml
```

## Notes

- You need enough free disk space for the upload and extracted contents.
- Password-protected archives may fail or only partially extract.
- RAR support depends on the 7z package available in the container.
- Do not expose this directly to the internet without authentication.
