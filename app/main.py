import hashlib
import json
import os
import shutil
import socket
import sqlite3
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

CLAMAV_HOST = os.getenv("CLAMAV_HOST", "clamav")
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "102400"))
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/uploads"))
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))

EXTRACT_TIMEOUT_SECONDS = int(os.getenv("EXTRACT_TIMEOUT_SECONDS", "7200"))
SCAN_SOCKET_TIMEOUT_SECONDS = int(os.getenv("SCAN_SOCKET_TIMEOUT_SECONDS", "600"))

MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
CLAMAV_INDIVIDUAL_FILE_LIMIT_BYTES = 2 * 1024 * 1024 * 1024

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz",
    ".iso", ".cab", ".wim", ".arj", ".lha", ".lzh",
}

app = FastAPI(title="Malware Checker")

static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")


def db_path() -> Path:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    return DATA_DIR / "scan_history.sqlite3"


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                filename TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                status TEXT NOT NULL,
                message TEXT NOT NULL,
                fully_scanned INTEGER NOT NULL,
                archive_detected INTEGER NOT NULL,
                scan_mode TEXT NOT NULL,
                files_extracted INTEGER NOT NULL,
                files_scanned INTEGER NOT NULL,
                files_skipped_large INTEGER NOT NULL,
                deleted_after_scan INTEGER NOT NULL,
                terminal_output TEXT NOT NULL,
                extra_json TEXT NOT NULL
            )
            """
        )
        conn.commit()


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    with get_db() as conn:
        conn.execute(
            """
            UPDATE scans
            SET status = 'scan_failed',
                message = 'Scan was interrupted because the server restarted before it finished.',
                fully_scanned = 0,
                deleted_after_scan = 0
            WHERE status IN ('queued', 'scanning', 'extracting')
            """
        )
        conn.commit()


def build_extra_json(result: dict) -> str:
    extra = {
        "threat": result.get("threat", ""),
        "threats": result.get("threats", []),
        "limited": result.get("limited", []),
        "failed": result.get("failed", []),
        "note": result.get("note", ""),
        "sha256": result.get("sha256", ""),
    }
    return json.dumps(extra)


def save_scan_record(result: dict, scan_id: Optional[str] = None) -> str:
    scan_id = scan_id or uuid.uuid4().hex
    created_at = datetime.now(timezone.utc).isoformat()

    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO scans (
                id, created_at, filename, size_bytes, status, message,
                fully_scanned, archive_detected, scan_mode,
                files_extracted, files_scanned, files_skipped_large,
                deleted_after_scan, terminal_output, extra_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                created_at,
                result.get("filename", "unknown"),
                int(result.get("size_bytes", 0)),
                result.get("status", "unknown"),
                result.get("message", ""),
                1 if result.get("fully_scanned") else 0,
                1 if result.get("archive_detected") else 0,
                result.get("scan_mode", "unknown"),
                int(result.get("files_extracted", 0) or 0),
                int(result.get("files_scanned", 0) or 0),
                int(result.get("files_skipped_large", 0) or 0),
                1 if result.get("deleted_after_scan") else 0,
                result.get("terminal_output", ""),
                build_extra_json(result),
            ),
        )
        conn.commit()

    return scan_id


def update_scan_record(scan_id: str, result: dict) -> None:
    with get_db() as conn:
        conn.execute(
            """
            UPDATE scans
            SET filename = ?,
                size_bytes = ?,
                status = ?,
                message = ?,
                fully_scanned = ?,
                archive_detected = ?,
                scan_mode = ?,
                files_extracted = ?,
                files_scanned = ?,
                files_skipped_large = ?,
                deleted_after_scan = ?,
                terminal_output = ?,
                extra_json = ?
            WHERE id = ?
            """,
            (
                result.get("filename", "unknown"),
                int(result.get("size_bytes", 0)),
                result.get("status", "unknown"),
                result.get("message", ""),
                1 if result.get("fully_scanned") else 0,
                1 if result.get("archive_detected") else 0,
                result.get("scan_mode", "unknown"),
                int(result.get("files_extracted", 0) or 0),
                int(result.get("files_scanned", 0) or 0),
                int(result.get("files_skipped_large", 0) or 0),
                1 if result.get("deleted_after_scan") else 0,
                result.get("terminal_output", ""),
                build_extra_json(result),
                scan_id,
            ),
        )
        conn.commit()

def row_to_record(row: sqlite3.Row, include_terminal: bool = False) -> dict:
    extra = json.loads(row["extra_json"] or "{}")

    record = {
        "id": row["id"],
        "created_at": row["created_at"],
        "filename": row["filename"],
        "size_bytes": row["size_bytes"],
        "status": row["status"],
        "message": row["message"],
        "fully_scanned": bool(row["fully_scanned"]),
        "archive_detected": bool(row["archive_detected"]),
        "scan_mode": row["scan_mode"],
        "files_extracted": row["files_extracted"],
        "files_scanned": row["files_scanned"],
        "files_skipped_large": row["files_skipped_large"],
        "deleted_after_scan": bool(row["deleted_after_scan"]),
        "threat": extra.get("threat", ""),
        "note": extra.get("note", ""),
        "sha256": extra.get("sha256", ""),
    }

    if include_terminal:
        record["terminal_output"] = row["terminal_output"]
        record["threats"] = extra.get("threats", [])
        record["limited"] = extra.get("limited", [])
        record["failed"] = extra.get("failed", [])

    return record


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


def is_rar_archive(filename: Optional[str]) -> bool:
    if not filename:
        return False
    lower = filename.lower()
    return lower.endswith(".rar")


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




def run_extractor(command: list[str], label: str) -> dict:
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
            "exit_code": -1,
            "output": "\n".join([
                f"$ {' '.join(command)}",
                "",
                f"========== {label} STDOUT ==========",
                stdout,
                "",
                f"========== {label} STDERR ==========",
                stderr,
                "",
                "ERROR: Archive extraction timed out.",
            ]).strip(),
        }

    output = "\n".join([
        f"$ {' '.join(command)}",
        "",
        f"========== {label} STDOUT ==========",
        completed.stdout or "",
        "",
        f"========== {label} STDERR ==========",
        completed.stderr or "",
        "",
        f"Exit code: {completed.returncode}",
    ]).strip()

    return {
        "ok": completed.returncode == 0,
        "exit_code": completed.returncode,
        "output": output,
    }


def finish_extraction_check(extract_dir: Path, output: str) -> dict:
    safe, reason = verify_extracted_paths_are_safe(extract_dir)
    if not safe:
        return {
            "ok": False,
            "output": output + "\n\nSECURITY ERROR: " + reason,
        }

    return {
        "ok": True,
        "output": output,
    }


def extract_archive(archive_path: Path, extract_dir: Path, original_filename: str = "") -> dict:
    extract_dir.mkdir(parents=True, exist_ok=True)

    # RAR files use official RARLAB unrar first. This has better RAR5 compatibility than 7z/unar.
    if is_rar_archive(original_filename):
        unrar_command = ["unrar", "x", "-o+", str(archive_path), str(extract_dir) + "/"]
        unrar = run_extractor(unrar_command, "OFFICIAL UNRAR")

        output = "\n\n".join([
            "========== RAR DETECTED ==========",
            "Original filename ends with .rar, so this scan used official RARLAB unrar first.",
            "",
            "========== EXTRACTOR: OFFICIAL UNRAR ==========",
            unrar["output"],
        ])

        if unrar["ok"]:
            checked = finish_extraction_check(extract_dir, output)
            checked["partial"] = False
            checked["partial_reason"] = ""
            return checked

        extracted_files = [p for p in extract_dir.rglob("*") if p.is_file() and not p.is_symlink()]
        if extracted_files:
            checked = finish_extraction_check(
                extract_dir,
                output + "\n\nWARNING: official unrar did not fully extract the archive, but some files were extracted and will be scanned."
            )
            checked["partial"] = True
            checked["partial_reason"] = "official unrar failed to fully extract the archive; only successfully extracted files can be scanned."
            return checked

        # If official unrar extracts nothing usable, try unar as a fallback.
        try:
            shutil.rmtree(extract_dir, ignore_errors=True)
            extract_dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

        unar_command = ["unar", "-force-overwrite", "-o", str(extract_dir), str(archive_path)]
        unar = run_extractor(unar_command, "UNAR FALLBACK")
        output = "\n\n".join([
            output,
            "",
            "========== EXTRACTOR FALLBACK: UNAR ==========",
            unar["output"],
        ])

        if not unar["ok"]:
            extracted_files = [p for p in extract_dir.rglob("*") if p.is_file() and not p.is_symlink()]
            if extracted_files:
                checked = finish_extraction_check(
                    extract_dir,
                    output + "\n\nWARNING: fallback unar did not fully extract the archive, but some files were extracted and will be scanned."
                )
                checked["partial"] = True
                checked["partial_reason"] = "all RAR extractors failed to fully extract the archive; only successfully extracted files can be scanned."
                return checked

            return {
                "ok": False,
                "partial": False,
                "partial_reason": "",
                "output": output + "\n\nERROR: official unrar and fallback unar both failed to extract any usable files from the RAR archive.",
            }

        checked = finish_extraction_check(extract_dir, output)
        checked["partial"] = False
        checked["partial_reason"] = ""
        return checked

    # Non-RAR archives use 7z first, then unar fallback.
    all_output = []

    seven_zip_command = ["7z", "x", "-y", f"-o{extract_dir}", str(archive_path)]
    seven_zip = run_extractor(seven_zip_command, "7Z")
    all_output.append("========== EXTRACTOR ATTEMPT 1: 7Z ==========")
    all_output.append(seven_zip["output"])

    if seven_zip["ok"]:
        checked = finish_extraction_check(extract_dir, "\n\n".join(all_output))
        checked["partial"] = False
        checked["partial_reason"] = ""
        return checked

    # Clean partial files before fallback so we do not scan incomplete extraction output.
    try:
        shutil.rmtree(extract_dir, ignore_errors=True)
        extract_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    unar_command = ["unar", "-force-overwrite", "-o", str(extract_dir), str(archive_path)]
    unar = run_extractor(unar_command, "UNAR")
    all_output.append("")
    all_output.append("========== EXTRACTOR ATTEMPT 2: UNAR ==========")
    all_output.append(unar["output"])

    if not unar["ok"]:
        extracted_files = [p for p in extract_dir.rglob("*") if p.is_file() and not p.is_symlink()]
        if extracted_files:
            checked = finish_extraction_check(
                extract_dir,
                "\n\n".join(all_output) + "\n\nWARNING: Extractors did not fully extract the archive, but some files were extracted and will be scanned."
            )
            checked["partial"] = True
            checked["partial_reason"] = "archive extraction was partial; only successfully extracted files can be scanned."
            return checked

        return {
            "ok": False,
            "partial": False,
            "partial_reason": "",
            "output": "\n\n".join(all_output) + "\n\nERROR: Both 7z and unar failed to extract any usable files.",
        }

    checked = finish_extraction_check(extract_dir, "\n\n".join(all_output))
    checked["partial"] = False
    checked["partial_reason"] = ""
    return checked


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


def scan_extracted_archive(archive_path: Path, extract_dir: Path, original_filename: str = "", progress_callback=None) -> dict:
    lines = [
        "========== SCAN MODE ==========",
        "Archive extraction scan",
        "",
        "========== EXTRACTION OUTPUT ==========",
    ]

    extraction = extract_archive(archive_path, extract_dir, original_filename)
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

    extraction_partial = bool(extraction.get("partial"))
    extraction_partial_reason = extraction.get("partial_reason", "")

    files = [p for p in extract_dir.rglob("*") if p.is_file() and not p.is_symlink()]

    infected = []
    limited = []
    failed = []

    if extraction_partial:
        limited.append(extraction_partial_reason or "Archive extraction was partial; some files were not scanned.")
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

    if progress_callback:
        progress_callback(
            status="scanning",
            message=f"Extraction complete. Scanning 0/{len(files)} extracted files.",
            files_extracted=len(files),
            files_scanned=0,
            files_skipped_large=0,
        )

    for index, extracted_file in enumerate(files, start=1):
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

        if progress_callback and (index == len(files) or index % 5 == 0):
            progress_callback(
                status="scanning",
                message=f"Scanning extracted files {index}/{len(files)}.",
                files_extracted=len(files),
                files_scanned=scanned_count,
                files_skipped_large=skipped_large_count,
            )

    fully_scanned = (not extraction_partial) and not limited and not failed and skipped_large_count == 0

    if infected:
        status = "infected"
        message = "Malware detected in extracted archive contents."
    elif limited or skipped_large_count:
        status = "scan_limited"
        if extraction_partial:
            message = "Archive was partially extracted. Successfully extracted files were scanned, but some files were not available to scan."
        else:
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
        f"Extraction partial: {'Yes' if extraction_partial else 'No'}",
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
        "threats": infected,
        "limited": limited,
        "failed": failed,
        "files_scanned": scanned_count,
        "files_extracted": len(files),
        "files_skipped_large": skipped_large_count,
        "scan_mode": "archive_extract",
    }


def run_scan_job(
    scan_id: str,
    file_path_text: str,
    extract_dir_text: str,
    display_name: str,
    archive_mode: bool,
    total_size: int,
    sha256: str,
) -> None:
    file_path = Path(file_path_text)
    extract_dir = Path(extract_dir_text)

    def set_progress(status: str, message: str, files_extracted: int = 0, files_scanned: int = 0, files_skipped_large: int = 0) -> None:
        update_scan_record(scan_id, {
            "filename": display_name,
            "size_bytes": total_size,
            "status": status,
            "message": message,
            "fully_scanned": False,
            "archive_detected": archive_mode,
            "scan_mode": "archive_extract" if archive_mode else "direct",
            "files_extracted": files_extracted,
            "files_scanned": files_scanned,
            "files_skipped_large": files_skipped_large,
            "deleted_after_scan": False,
            "terminal_output": message,
            "note": "The uploaded file is temporarily kept only while the background scan runs.",
            "sha256": sha256,
        })

    set_progress("extracting" if archive_mode else "scanning", "Background job started. Extracting archive..." if archive_mode else "Background job started. Scanning file...")

    try:
        if archive_mode:
            result = scan_extracted_archive(
                file_path,
                extract_dir,
                display_name,
                progress_callback=set_progress,
            )
        else:
            result = scan_regular_file(file_path)

        result.update({
            "filename": display_name,
            "size_bytes": total_size,
            "deleted_after_scan": True,
            "archive_detected": archive_mode,
            "sha256": sha256,
            "note": "Only this scan record is stored. The uploaded file and extracted files were deleted after scanning.",
        })

        update_scan_record(scan_id, result)

    except Exception as exc:
        update_scan_record(scan_id, {
            "filename": display_name,
            "size_bytes": total_size,
            "status": "scan_failed",
            "message": f"Background scan crashed: {exc}",
            "fully_scanned": False,
            "archive_detected": archive_mode,
            "scan_mode": "archive_extract" if archive_mode else "direct",
            "files_extracted": 0,
            "files_scanned": 0,
            "files_skipped_large": 0,
            "deleted_after_scan": True,
            "terminal_output": f"ERROR: Background scan crashed: {exc}",
            "note": "The uploaded file and extracted files were deleted after the failed scan attempt.",
            "sha256": sha256,
        })

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
        "history": "enabled",
    }


@app.get("/api/scans")
def list_scans():
    init_db()
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
    return {"records": [row_to_record(row, include_terminal=True) for row in rows]}


@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    init_db()
    with get_db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Scan record not found.")
    return row_to_record(row, include_terminal=True)


@app.delete("/api/scans")
def clear_scans():
    init_db()
    with get_db() as conn:
        conn.execute("DELETE FROM scans")
        conn.commit()
    return {"ok": True}


@app.post("/api/scan")
async def scan(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    if not wait_for_clamav(timeout_seconds=3):
        raise HTTPException(
            status_code=503,
            detail="ClamAV is not ready yet. Wait a minute for virus definitions to load, then try again.",
        )

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    scan_id = uuid.uuid4().hex
    file_path = UPLOAD_DIR / f"{scan_id}.upload"
    extract_dir = UPLOAD_DIR / f"{scan_id}_extracted"

    display_name = safe_display_name(file.filename)
    archive_mode = is_archive(display_name)

    total = 0
    sha256_hash = hashlib.sha256()

    with file_path.open("wb") as out:
        while True:
            chunk = await file.read(1024 * 1024)
            if not chunk:
                break

            total += len(chunk)
            sha256_hash.update(chunk)
            if total > MAX_UPLOAD_BYTES:
                try:
                    file_path.unlink()
                except Exception:
                    pass
                raise HTTPException(
                    status_code=413,
                    detail=f"File too large. Limit is {MAX_UPLOAD_MB} MB.",
                )

            out.write(chunk)

    os.chmod(file_path, 0o644)
    sha256 = sha256_hash.hexdigest()

    queued_result = {
        "filename": display_name,
        "size_bytes": total,
        "status": "queued",
        "message": "Upload complete. Scan queued in the background. You can close this page now and come back later.",
        "fully_scanned": False,
        "archive_detected": archive_mode,
        "scan_mode": "archive_extract" if archive_mode else "direct",
        "files_extracted": 0,
        "files_scanned": 0,
        "files_skipped_large": 0,
        "deleted_after_scan": False,
        "terminal_output": "Upload complete. Background scan queued.",
        "note": "The uploaded file is stored only while the background scan runs. It will be deleted after scanning.",
        "sha256": sha256,
    }

    save_scan_record(queued_result, scan_id=scan_id)

    background_tasks.add_task(
        run_scan_job,
        scan_id,
        str(file_path),
        str(extract_dir),
        display_name,
        archive_mode,
        total,
        sha256,
    )

    queued_result["scan_id"] = scan_id
    return JSONResponse(queued_result)
