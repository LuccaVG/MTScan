const state = {
  currentScanId: null,
  pollTimer: null,
  scans: []
};

const severityColors = {
  critical: "#bd2f2f",
  high: "#d9542b",
  medium: "#c17a00",
  low: "#2764d9",
  info: "#0f8b8d",
  unknown: "#667085"
};

const els = {
  form: document.getElementById("scanForm"),
  target: document.getElementById("targetInput"),
  profile: document.getElementById("profileSelect"),
  topPorts: document.getElementById("topPortsInput"),
  timeout: document.getElementById("timeoutInput"),
  severity: document.getElementById("severitySelect"),
  dryRun: document.getElementById("dryRunInput"),
  jsonOutput: document.getElementById("jsonOutputInput"),
  formError: document.getElementById("formError"),
  refreshHealth: document.getElementById("refreshHealth"),
  environment: document.getElementById("environmentText"),
  scanTitle: document.getElementById("scanTitle"),
  scanSubtitle: document.getElementById("scanSubtitle"),
  scanState: document.getElementById("scanState"),
  openPorts: document.getElementById("openPortsMetric"),
  http: document.getElementById("httpMetric"),
  risk: document.getElementById("riskMetric"),
  observations: document.getElementById("observationMetric"),
  log: document.getElementById("logOutput"),
  findings: document.getElementById("findingsTable"),
  files: document.getElementById("filesList"),
  history: document.getElementById("scanHistory"),
  severityChart: document.getElementById("severityChart"),
  surfaceChart: document.getElementById("surfaceChart")
};

function selectedMode() {
  const checked = document.querySelector("input[name='mode']:checked");
  return checked ? checked.value : "chain";
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || `Request failed with ${response.status}`);
  }
  return data;
}

function scanPayload() {
  return {
    target: els.target.value.trim(),
    mode: selectedMode(),
    profile: els.profile.value,
    dry_run: els.dryRun.checked,
    json_output: els.jsonOutput.checked,
    options: {
      top_ports: els.topPorts.value,
      timeout: els.timeout.value,
      severity: els.severity.value
    }
  };
}

async function refreshHealth() {
  try {
    const health = await api("/api/health");
    const toolText = Object.entries(health.tools || {})
      .map(([tool, info]) => `${tool}: ${info.available === "yes" ? "ok" : "missing"}`)
      .join(" | ");
    els.environment.textContent = `${health.platform}; ${toolText}`;
  } catch (error) {
    els.environment.textContent = error.message;
  }
}

async function startScan(event) {
  event.preventDefault();
  els.formError.textContent = "";
  els.form.querySelector(".primary-button").disabled = true;
  try {
    const scan = await api("/api/scans", {
      method: "POST",
      body: JSON.stringify(scanPayload())
    });
    state.currentScanId = scan.id;
    renderScan(scan);
    await refreshScans();
    startPolling();
  } catch (error) {
    els.formError.textContent = error.message;
  } finally {
    els.form.querySelector(".primary-button").disabled = false;
  }
}

function startPolling() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
  }
  state.pollTimer = setInterval(loadCurrentScan, 1200);
  loadCurrentScan();
}

async function loadCurrentScan() {
  if (!state.currentScanId) {
    return;
  }
  try {
    const scan = await api(`/api/scans/${state.currentScanId}`);
    renderScan(scan);
    await refreshScans();
    if (!["queued", "running"].includes(scan.status) && state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
    }
  } catch (error) {
    els.formError.textContent = error.message;
  }
}

async function refreshScans() {
  try {
    const data = await api("/api/scans");
    state.scans = data.scans || [];
    renderHistory();
  } catch (error) {
    els.history.textContent = error.message;
  }
}

function renderScan(scan) {
  const summary = scan.summary || {};
  els.scanTitle.textContent = scan.target ? `${scan.mode.toUpperCase()} - ${scan.target}` : "No scan selected";
  els.scanSubtitle.textContent = scan.error || scan.output_dir || scan.started_at || "Ready";
  els.scanState.textContent = scan.status || "Idle";
  els.scanState.className = `state-badge ${scan.status || "idle"}`;
  els.openPorts.textContent = summary.open_ports || 0;
  els.http.textContent = summary.http_services || 0;
  els.risk.textContent = summary.security_findings || 0;
  els.observations.textContent = summary.observations || 0;
  els.log.textContent = (scan.lines || []).join("\n");
  els.log.scrollTop = els.log.scrollHeight;
  renderFindings(summary.findings || []);
  renderFiles(scan);
  drawSeverityChart(summary.severity_counts || {});
  drawSurfaceChart(summary);
}

function renderFindings(findings) {
  els.findings.replaceChildren();
  if (!findings.length) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 3;
    cell.textContent = "No findings";
    row.appendChild(cell);
    els.findings.appendChild(row);
    return;
  }
  findings.forEach((finding) => {
    const row = document.createElement("tr");
    ["severity", "name", "matched_at"].forEach((key) => {
      const cell = document.createElement("td");
      cell.textContent = finding[key] || "N/A";
      row.appendChild(cell);
    });
    els.findings.appendChild(row);
  });
}

function renderFiles(scan) {
  els.files.replaceChildren();
  const rows = [];
  if (scan.output_dir) {
    rows.push({ label: "Output directory", value: scan.output_dir });
  }
  (scan.results || []).forEach((result) => {
    if (result.output_file) {
      rows.push({ label: `${result.tool} output`, value: result.output_file });
    }
  });
  if (!rows.length) {
    els.files.textContent = "No files";
    return;
  }
  rows.forEach((item) => {
    const row = document.createElement("div");
    row.className = "file-row";
    row.textContent = item.label;
    const value = document.createElement("span");
    value.textContent = item.value;
    row.appendChild(value);
    els.files.appendChild(row);
  });
}

function renderHistory() {
  els.history.replaceChildren();
  if (!state.scans.length) {
    els.history.textContent = "No scans";
    return;
  }
  state.scans.forEach((scan) => {
    const row = document.createElement("div");
    row.className = `scan-row ${scan.id === state.currentScanId ? "active" : ""}`;
    row.tabIndex = 0;
    row.textContent = `${scan.mode.toUpperCase()} - ${scan.target}`;
    const detail = document.createElement("span");
    detail.textContent = `${scan.status} | ${scan.created_at}`;
    row.appendChild(detail);
    row.addEventListener("click", () => {
      state.currentScanId = scan.id;
      renderScan(scan);
      startPolling();
    });
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        row.click();
      }
    });
    els.history.appendChild(row);
  });
}

function canvasContext(canvas) {
  const ratio = window.devicePixelRatio || 1;
  const width = Math.max(280, Math.floor(canvas.clientWidth));
  const height = Math.max(180, Math.floor(canvas.clientHeight));
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);
  return { ctx, width, height };
}

function drawSeverityChart(counts) {
  const labels = ["critical", "high", "medium", "low", "info"];
  const values = labels.map((label) => Number(counts[label] || 0));
  const { ctx, width, height } = canvasContext(els.severityChart);
  const maxValue = Math.max(1, ...values);
  const chartTop = 18;
  const chartBottom = height - 34;
  const barWidth = Math.max(24, (width - 50) / labels.length - 14);
  ctx.font = "12px Segoe UI, Arial";
  labels.forEach((label, index) => {
    const x = 34 + index * ((width - 50) / labels.length);
    const barHeight = ((chartBottom - chartTop) * values[index]) / maxValue;
    ctx.fillStyle = severityColors[label];
    ctx.fillRect(x, chartBottom - barHeight, barWidth, barHeight);
    ctx.fillStyle = "#18202f";
    ctx.fillText(String(values[index]), x, chartBottom - barHeight - 6);
    ctx.fillStyle = "#667085";
    ctx.fillText(label, x, height - 12);
  });
}

function drawSurfaceChart(summary) {
  const labels = ["Ports", "HTTP", "Findings"];
  const values = [
    Number(summary.open_ports || 0),
    Number(summary.http_services || 0),
    Number(summary.findings_total || 0)
  ];
  const colors = ["#2764d9", "#0f8b8d", "#c17a00"];
  const { ctx, width, height } = canvasContext(els.surfaceChart);
  const total = values.reduce((sum, value) => sum + value, 0);
  const cx = width * 0.34;
  const cy = height * 0.5;
  const radius = Math.min(width, height) * 0.31;
  let angle = -Math.PI / 2;

  if (!total) {
    ctx.strokeStyle = "#d9dee8";
    ctx.lineWidth = 24;
    ctx.beginPath();
    ctx.arc(cx, cy, radius, 0, Math.PI * 2);
    ctx.stroke();
  } else {
    values.forEach((value, index) => {
      const slice = (value / total) * Math.PI * 2;
      ctx.strokeStyle = colors[index];
      ctx.lineWidth = 24;
      ctx.beginPath();
      ctx.arc(cx, cy, radius, angle, angle + slice);
      ctx.stroke();
      angle += slice;
    });
  }

  ctx.font = "13px Segoe UI, Arial";
  labels.forEach((label, index) => {
    const y = 54 + index * 34;
    ctx.fillStyle = colors[index];
    ctx.fillRect(width * 0.62, y - 10, 12, 12);
    ctx.fillStyle = "#18202f";
    ctx.fillText(`${label}: ${values[index]}`, width * 0.62 + 20, y);
  });
}

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((item) => item.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById(`${tab.dataset.tab}Tab`).classList.add("active");
  });
});

els.form.addEventListener("submit", startScan);
els.refreshHealth.addEventListener("click", refreshHealth);
window.addEventListener("resize", () => {
  const scan = state.scans.find((item) => item.id === state.currentScanId);
  if (scan) {
    drawSeverityChart((scan.summary || {}).severity_counts || {});
    drawSurfaceChart(scan.summary || {});
  }
});

refreshHealth();
refreshScans();
drawSeverityChart({});
drawSurfaceChart({});
