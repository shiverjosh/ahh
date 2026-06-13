import os
import shutil
import socket
import subprocess
import time
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

CLAMAV_HOST = os.getenv("CLAMAV_HOST", "clamav")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "102400"))
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/uploads"))

EXTRACT_TIMEOUT_SECONDS = int(os.getenv("EXTRACT_TIMEOUT_SECONDS", "7200"))
SCAN_SOCKET_TIMEOUT_SECONDS = int(os.getenv("SCAN_SOCKET_TIMEOUT_SECONDS", "600"))

MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

# ClamAV cannot reliably fully scan individual files larger than ~2GB.
# Large archives are extracted first; extracted files over this size are skipped and reported.
CLAMAV_INDIVIDUAL_FILE_LIMIT_BYTES = 2 * 1024 * 1024 * 1024

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".iso", ".cab", ".wim", ".arj", ".lha", ".lzh",
}

app = FastAPI(title="Malware Checker")

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


def safe_display_name(filename: Optional[str]) -> str:
    if not filename:
        return "uploaded-file"
    return Path(filename).name[:180]


def is_archive(filename: Optional[str]) -> bool:
    if not filename:
        return False
    lower = filename.lower()
    if lower.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
        return True
    return Path(lower).suffix in ARCHIVE_EXTENSIONS


def wait_for_clamav(timeout_seconds: int = 3) -> bool:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        try:
            with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=2) as sock:
                sock.sendall(b"PING\n")
                response = sock.recv(1024).decode(errors="replace").strip()
                return response == "PONG"
        except OSError:
            time.sleep(0.4)
    return False


def parse_threat_from_response(response: str) -> str:
    try:
        return response.split(": ", 1)[1].replace(" FOUND", "").strip()
    except IndexError:
        return "Unknown"


def scan_one_path_with_clamav(file_path: Path) -> dict:
    command = f"SCAN {file_path}\n".encode()

    try:
        with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=SCAN_SOCKET_TIMEOUT_SECONDS) as sock:
            sock.sendall(command)
            response = sock.recv(4096).decode(errors="replace").strip()
    except socket.timeout:
        response = f"{file_path}: ERROR: ClamAV scan timed out"
        return {"status": "scan_failed", "fully_scanned": False, "raw": response, "threat": ""}
    except OSError as exc:
        response = f"{file_path}: ERROR: Could not connect to ClamAV: {exc}"
        return {"status": "scan_failed", "fully_scanned": False, "raw": response, "threat": ""}

    if response.endswith(" OK"):
        return {"status": "clean", "fully_scanned": True, "raw": response, "threat": ""}

    if response.endswith(" FOUND"):
        threat = parse_threat_from_response(response)
        if threat.startswith("Heuristics.Limits.Exceeded"):
            return {"status": "scan_limited", "fully_scanned": False, "raw": response, "threat": threat}
        return {"status": "infected", "fully_scanned": True, "raw": response, "threat": threat}

    return {"status": "scan_failed", "fully_scanned": False, "raw": response, "threat": ""}


def verify_extracted_paths_are_safe(extract_dir: Path) -> tuple[bool, str]:
    root = extract_dir.resolve()
    for path in extract_dir.rglob("*"):
        try:
            resolved = path.resolve()
        except OSError:
            return False, f"Could not resolve extracted path: {path}"
        if not str(resolved).startswith(str(root)):
            return False, f"Unsafe extracted path detected: {path}"
        if path.is_symlink():
            return False, f"Symlink detected and blocked: {path}"
    return True, ""


def extract_archive(archive_path: Path, extract_dir: Path) -> dict:
    extract_dir.mkdir(parents=True, exist_ok=True)

    command = ["7z", "x", "-y", f"-o{extract_dir}", str(archive_path)]

    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=EXTRACT_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        return {
            "ok": False,
            "output": "\n".join([
                "$ " + " ".join(command),
                stdout,
                stderr,
                "ERROR: Archive extraction timed out.",
            ]).strip(),
        }

    output = "\n".join([
        "$ " + " ".join(command),
        "",
        "========== 7Z STDOUT ==========",
        completed.stdout or "",
        "",
        "========== 7Z STDERR ==========",
        completed.stderr or "",
        "",
        f"Exit code: {completed.returncode}",
    ]).strip()

    if completed.returncode != 0:
        return {"ok": False, "output": output}

    safe, reason = verify_extracted_paths_are_safe(extract_dir)
    if not safe:
        return {"ok": False, "output": output + "\n\nSECURITY ERROR: " + reason}

    return {"ok": True, "output": output}


def scan_regular_file(file_path: Path) -> dict:
    lines = ["========== SCAN MODE ==========", "Direct file scan", "", "========== CLAMAV RAW OUTPUT =========="]

    if file_path.stat().st_size > CLAMAV_INDIVIDUAL_FILE_LIMIT_BYTES:
        raw = f"{file_path}: SKIPPED_LARGE_FILE_OVER_2GB"
        lines += [
            raw, "", "========== PARSED RESULT ==========",
            "Status: scan_limited",
            "Fully scanned: No",
            "Reason: File is larger than ClamAV's individual file scan limit.",
        ]
        return {
            "status": "scan_limited",
            "message": "Scan incomplete. This individual file is larger than ClamAV can fully scan.",
            "fully_scanned": False,
            "terminal_output": "\n".join(lines),
            "threat": "Individual file over ClamAV limit",
            "files_scanned": 0,
            "files_extracted": 0,
            "files_skipped_large": 1,
            "scan_mode": "direct",
        }

    result = scan_one_path_with_clamav(file_path)
    status = result["status"]
    message = {
        "clean": "No malware detected by ClamAV.",
        "infected": "Malware detected.",
        "scan_limited": "Scan incomplete. ClamAV hit a scan limit.",
        "scan_failed": "ClamAV returned an error or unknown result.",
    }.get(status, "Unknown result.")

    lines += [
        result["raw"], "", "========== PARSED RESULT ==========",
        f"Status: {status}",
        f"Fully scanned: {'Yes' if result['fully_scanned'] else 'No'}",
        f"Reason: {result.get('threat') or 'None'}",
    ]

    return {
        "status": status,
        "message": message,
        "fully_scanned": result["fully_scanned"],
        "terminal_output": "\n".join(lines),
        "threat": result.get("threat", ""),
        "files_scanned": 1 if status in {"clean", "infected"} else 0,
        "files_extracted": 0,
        "files_skipped_large": 0,
        "scan_mode": "direct",
    }


def scan_extracted_archive(archive_path: Path, extract_dir: Path) -> dict:
    lines = [
        "========== SCAN MODE ==========",
        "Archive extraction scan",
        "",
        "========== EXTRACTION OUTPUT ==========",
    ]

    extraction = extract_archive(archive_path, extract_dir)
    lines.append(extraction["output"])

    if not extraction["ok"]:
        lines += [
            "", "========== PARSED RESULT ==========",
            "Status: scan_failed",
            "Fully scanned: No",
            "Reason: Archive extraction failed.",
        ]
        return {
            "status": "scan_failed",
            "message": "Archive extraction failed. The file was not fully scanned.",
            "fully_scanned": False,
            "terminal_output": "\n".join(lines),
            "threat": "",
            "files_scanned": 0,
            "files_extracted": 0,
            "files_skipped_large": 0,
            "scan_mode": "archive_extract",
        }

    files = [p for p in extract_dir.rglob("*") if p.is_file() and not p.is_symlink()]

    infected = []
    limited = []
    failed = []
    scanned_count = 0
    skipped_large_count = 0

    lines += [
        "",
        "========== EXTRACTED FILES ==========",
        f"Extracted files found: {len(files)}",
        "",
        "========== CLAMAV RAW OUTPUT ==========",
    ]

    if not files:
        lines.append("No files found after extraction.")

    for extracted_file in files:
        relative_name = str(extracted_file.relative_to(extract_dir))

        try:
            file_size = extracted_file.stat().st_size
        except OSError as exc:
            failed.append(f"{relative_name}: could not stat file: {exc}")
            lines.append(f"{extracted_file}: ERROR could not stat file: {exc}")
            continue

        if file_size > CLAMAV_INDIVIDUAL_FILE_LIMIT_BYTES:
            skipped_large_count += 1
            limited.append(f"{relative_name}: skipped, file over 2GB")
            lines.append(f"{extracted_file}: SKIPPED_LARGE_FILE_OVER_2GB")
            continue

        result = scan_one_path_with_clamav(extracted_file)
        lines.append(result["raw"])

        if result["status"] == "infected":
            infected.append(f"{relative_name}: {result.get('threat', 'Unknown threat')}")
        elif result["status"] == "scan_limited":
            limited.append(f"{relative_name}: {result.get('threat', 'Scan limited')}")
        elif result["status"] == "scan_failed":
            failed.append(f"{relative_name}: scan failed")

        if result["status"] in {"clean", "infected"}:
            scanned_count += 1

    fully_scanned = not infected and not limited and not failed and skipped_large_count == 0

    if infected:
        status = "infected"
        message = "Malware detected in extracted archive contents."
    elif limited or skipped_large_count:
        status = "scan_limited"
        message = "Archive was extracted, but some files could not be fully scanned."
    elif failed:
        status = "scan_failed"
        message = "Archive was extracted, but one or more scans failed."
    else:
        status = "clean"
        message = "Archive extracted and no malware was detected in scanned files."

    lines += [
        "",
        "========== PARSED RESULT ==========",
        f"Status: {status}",
        f"Fully scanned: {'Yes' if fully_scanned else 'No'}",
        f"Files extracted: {len(files)}",
        f"Files scanned: {scanned_count}",
        f"Files skipped large: {skipped_large_count}",
        f"Threats found: {len(infected)}",
        f"Limited scans: {len(limited)}",
        f"Failed scans: {len(failed)}",
    ]

    if infected:
        lines += ["", "========== THREATS =========="] + infected
    if limited:
        lines += ["", "========== LIMITED / SKIPPED =========="] + limited
    if failed:
        lines += ["", "========== FAILED =========="] + failed

    return {
        "status": status,
        "message": message,
        "fully_scanned": fully_scanned,
        "terminal_output": "\n".join(lines),
        "threat": infected[0] if infected else (limited[0] if limited else ""),
        "files_scanned": scanned_count,
        "files_extracted": len(files),
        "files_skipped_large": skipped_large_count,
        "scan_mode": "archive_extract",
    }


@app.get("/")
def home():
    return FileResponse(static_dir / "index.html")


@app.get("/api/health")
def health():
    return {
        "app": "ok",
        "clamav": "ok" if wait_for_clamav(timeout_seconds=1) else "not_ready",
        "max_upload_mb": MAX_UPLOAD_MB,
        "archive_extract": "enabled",
    }


@app.post("/api/scan")
async def scan(file: UploadFile = File(...)):
    if not wait_for_clamav(timeout_seconds=3):
        raise HTTPException(
            status_code=503,
            detail="ClamAV is not ready yet. Wait a minute for virus definitions to load, then try again.",
        )

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    random_id = uuid.uuid4().hex
    file_path = UPLOAD_DIR / f"{random_id}.upload"
    extract_dir = UPLOAD_DIR / f"{random_id}_extracted"

    display_name = safe_display_name(file.filename)
    archive_mode = is_archive(display_name)

    total = 0

    try:
        with file_path.open("wb") as out:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break

                total += len(chunk)
                if total > MAX_UPLOAD_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large. Limit is {MAX_UPLOAD_MB} MB.",
                    )

                out.write(chunk)

        os.chmod(file_path, 0o644)

        result = scan_extracted_archive(file_path, extract_dir) if archive_mode else scan_regular_file(file_path)

        result.update({
            "filename": display_name,
            "size_bytes": total,
            "deleted_after_scan": True,
            "archive_detected": archive_mode,
            "note": (
                "Clean means ClamAV did not detect malware in the files it scanned. "
                "If fully_scanned is false, one or more files were skipped, limited, or failed."
            ),
        })

        return JSONResponse(result)

    finally:
        try:
            if file_path.exists():
                file_path.unlink()
        except Exception:
            pass

        try:
            if extract_dir.exists():
                shutil.rmtree(extract_dir, ignore_errors=True)
        except Exception:
            pass
