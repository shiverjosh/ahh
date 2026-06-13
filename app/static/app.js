const fileInput = document.getElementById("fileInput");
const scanBtn = document.getElementById("scanBtn");
const selectedFileText = document.getElementById("selectedFile");
const progress = document.getElementById("progress");
const resultBox = document.getElementById("result");
const health = document.getElementById("health");

let selectedFile = null;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function formatBytes(bytes) {
  if (!bytes && bytes !== 0) return "Unknown";

  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = bytes;
  let unit = 0;

  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit++;
  }

  return `${size.toFixed(unit === 0 ? 0 : 2)} ${units[unit]}`;
}

function renderResult(data) {
  const status = data.status || "error";

  const statusLabels = {
    clean: "CLEAN",
    infected: "INFECTED",
    scan_limited: "SCAN INCOMPLETE",
    scan_failed: "SCAN FAILED",
    error: "ERROR",
  };

  const output = data.terminal_output || data.raw || "";

  resultBox.className = status;
  resultBox.classList.remove("hidden");

  resultBox.innerHTML = `
    <h2>${escapeHtml(statusLabels[status] || "RESULT")}</h2>

    <p>File: ${escapeHtml(data.filename || selectedFile?.name || "Unknown")}</p>
    <p>Size: ${formatBytes(data.size_bytes || selectedFile?.size)}</p>
    <p>Status: ${escapeHtml(status)}</p>
    <p>Fully scanned: ${data.fully_scanned === true ? "Yes" : "No"}</p>
    <p>Archive detected: ${data.archive_detected ? "Yes" : "No"}</p>
    <p>Scan mode: ${escapeHtml(data.scan_mode || "unknown")}</p>
    <p>Files extracted: ${data.files_extracted ?? 0}</p>
    <p>Files scanned: ${data.files_scanned ?? 0}</p>
    <p>Files skipped large: ${data.files_skipped_large ?? 0}</p>
    <p>Message: ${escapeHtml(data.message || "")}</p>
    <p>Deleted after scan: ${data.deleted_after_scan ? "Yes" : "Unknown"}</p>
    <p>Note: ${escapeHtml(data.note || "")}</p>

    <h3>Terminal output</h3>
    <pre>${escapeHtml(output)}</pre>
  `;
}

fileInput.addEventListener("change", () => {
  selectedFile = fileInput.files[0] || null;
  scanBtn.disabled = !selectedFile;

  selectedFileText.textContent = selectedFile
    ? `${selectedFile.name} (${formatBytes(selectedFile.size)})`
    : "No file selected.";
});

scanBtn.addEventListener("click", async () => {
  if (!selectedFile) return;

  progress.classList.remove("hidden");
  resultBox.classList.add("hidden");
  scanBtn.disabled = true;

  const formData = new FormData();
  formData.append("file", selectedFile);

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      body: formData,
    });

    const data = await response.json();

    if (!response.ok) {
      renderResult({
        status: "error",
        filename: selectedFile.name,
        size_bytes: selectedFile.size,
        fully_scanned: false,
        message: data.detail || "Upload or scan failed.",
        terminal_output: JSON.stringify(data, null, 2),
      });
    } else {
      renderResult(data);
    }
  } catch (error) {
    renderResult({
      status: "error",
      filename: selectedFile.name,
      size_bytes: selectedFile.size,
      fully_scanned: false,
      message: error.message,
      terminal_output: error.stack || error.message,
    });
  } finally {
    progress.classList.add("hidden");
    scanBtn.disabled = false;
  }
});

async function checkHealth() {
  try {
    const response = await fetch("/api/health");
    const data = await response.json();

    health.textContent = `Scanner: ${data.clamav} | Max upload: ${data.max_upload_mb} MB | Archive extraction: ${data.archive_extract}`;
  } catch {
    health.textContent = "Scanner status unavailable.";
  }
}

checkHealth();
setInterval(checkHealth, 10000);
