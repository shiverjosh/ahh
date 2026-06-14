const fileInput = document.getElementById("fileInput");
const scanBtn = document.getElementById("scanBtn");
const clearBtn = document.getElementById("clearBtn");
const selectedFileText = document.getElementById("selectedFile");
const progress = document.getElementById("progress");
const currentResult = document.getElementById("currentResult");
const historyBox = document.getElementById("history");
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

function label(status) {
  return {
    clean: "CLEAN",
    infected: "INFECTED",
    scan_limited: "SCAN INCOMPLETE",
    scan_failed: "SCAN FAILED",
    error: "ERROR",
  }[status] || "RESULT";
}

function renderResult(data, titlePrefix = "Current scan") {
  const output = data.terminal_output || data.raw || "";

  return `
    <h2>${escapeHtml(titlePrefix)}: ${escapeHtml(label(data.status))}</h2>
    <p>ID: ${escapeHtml(data.scan_id || data.id || "")}</p>
    <p>Date: ${escapeHtml(data.created_at || "just now")}</p>
    <p>File: ${escapeHtml(data.filename || selectedFile?.name || "Unknown")}</p>
    <p>Size: ${formatBytes(data.size_bytes || selectedFile?.size)}</p>
    <p>Status: ${escapeHtml(data.status || "unknown")}</p>
    <p>Fully scanned: ${data.fully_scanned === true ? "Yes" : "No"}</p>
    <p>Archive detected: ${data.archive_detected ? "Yes" : "No"}</p>
    <p>Scan mode: ${escapeHtml(data.scan_mode || "unknown")}</p>
    <p>Files extracted: ${data.files_extracted ?? 0}</p>
    <p>Files scanned: ${data.files_scanned ?? 0}</p>
    <p>Files skipped large: ${data.files_skipped_large ?? 0}</p>
    <p>Deleted after scan: ${data.deleted_after_scan ? "Yes" : "Unknown"}</p>
    <p>Message: ${escapeHtml(data.message || "")}</p>
    <p>Note: ${escapeHtml(data.note || "")}</p>

    <details>
      <summary>Terminal output</summary>
      <pre>${escapeHtml(output)}</pre>
    </details>
  `;
}

function renderHistory(records) {
  if (!records.length) {
    historyBox.innerHTML = "<p>No previous scans.</p>";
    return;
  }

  historyBox.innerHTML = records.map((record) => {
    return `
      <article class="record">
        <details>
          <summary>
            ${escapeHtml(label(record.status))} |
            ${escapeHtml(record.filename)} |
            ${formatBytes(record.size_bytes)} |
            ${escapeHtml(record.created_at)}
          </summary>
          ${renderResult(record, "Previous scan")}
        </details>
      </article>
    `;
  }).join("");
}

async function loadHistory() {
  try {
    const response = await fetch("/api/scans");
    const data = await response.json();
    renderHistory(data.records || []);
  } catch {
    historyBox.innerHTML = "<p>Could not load previous scans.</p>";
  }
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
  currentResult.classList.add("hidden");
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
      currentResult.innerHTML = renderResult({
        status: "error",
        filename: selectedFile.name,
        size_bytes: selectedFile.size,
        fully_scanned: false,
        message: data.detail || "Upload or scan failed.",
        terminal_output: JSON.stringify(data, null, 2),
      });
    } else {
      currentResult.innerHTML = renderResult(data);
      await loadHistory();
    }

    currentResult.classList.remove("hidden");
  } catch (error) {
    currentResult.innerHTML = renderResult({
      status: "error",
      filename: selectedFile.name,
      size_bytes: selectedFile.size,
      fully_scanned: false,
      message: error.message,
      terminal_output: error.stack || error.message,
    });
    currentResult.classList.remove("hidden");
  } finally {
    progress.classList.add("hidden");
    scanBtn.disabled = false;
  }
});

clearBtn.addEventListener("click", async () => {
  const ok = confirm("Clear ALL saved scan records? This only deletes the stored reports/history. Uploaded files are already deleted after scanning.");
  if (!ok) return;

  await fetch("/api/scans", { method: "DELETE" });
  await loadHistory();
  currentResult.classList.add("hidden");
});

async function checkHealth() {
  try {
    const response = await fetch("/api/health");
    const data = await response.json();

    health.textContent = `Scanner: ${data.clamav} | Max upload: ${data.max_upload_mb} MB | Archive extraction: ${data.archive_extract} | History: ${data.history}`;
  } catch {
    health.textContent = "Scanner status unavailable.";
  }
}

checkHealth();
loadHistory();
setInterval(checkHealth, 10000);
