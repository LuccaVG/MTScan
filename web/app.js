const state = {
  auth: null,
  currentScanId: null,
  pollTimer: null,
  dataTimer: null,
  scans: [],
  schedules: [],
  overview: {},
  health: {}
};

const severityColors = {
  critical: "#b83232",
  high: "#c44a1f",
  medium: "#b36a00",
  low: "#245fc8",
  info: "#0b8587",
  unknown: "#65728a"
};

const $ = (id) => document.getElementById(id);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

const els = {
  authScreen: $("authScreen"),
  appShell: $("appShell"),
  authMessage: $("authMessage"),
  loginForm: $("loginForm"),
  firstPasswordForm: $("firstPasswordForm"),
  loginUsername: $("loginUsername"),
  loginPassword: $("loginPassword"),
  firstCurrentPassword: $("firstCurrentPassword"),
  firstNewPassword: $("firstNewPassword"),
  firstConfirmPassword: $("firstConfirmPassword"),
  loginError: $("loginError"),
  firstPasswordError: $("firstPasswordError"),
  userBadge: $("userBadge"),
  logoutButton: $("logoutButton"),
  refreshAll: $("refreshAll"),
  environment: $("environmentText"),
  dashboardStorage: $("dashboardStorage"),
  totalScansMetric: $("totalScansMetric"),
  assetMetric: $("assetMetric"),
  totalRiskMetric: $("totalRiskMetric"),
  criticalMetric: $("criticalMetric"),
  activeScheduleMetric: $("activeScheduleMetric"),
  totalHttpMetric: $("totalHttpMetric"),
  latestScanSummary: $("latestScanSummary"),
  dashboardFindings: $("dashboardFindingsTable"),
  dashboardSchedules: $("dashboardSchedulesTable"),
  dashboardSeverityChart: $("dashboardSeverityChart"),
  dashboardHistoryChart: $("dashboardHistoryChart"),
  dashboardCategoryChart: $("dashboardCategoryChart"),
  form: $("scanForm"),
  target: $("targetInput"),
  profile: $("profileSelect"),
  ports: $("portsInput"),
  topPorts: $("topPortsInput"),
  timeout: $("timeoutInput"),
  tags: $("tagsInput"),
  templates: $("templatesInput"),
  severity: $("severitySelect"),
  dryRun: $("dryRunInput"),
  jsonOutput: $("jsonOutputInput"),
  formError: $("formError"),
  scanTitle: $("scanTitle"),
  scanSubtitle: $("scanSubtitle"),
  scanState: $("scanState"),
  openPorts: $("openPortsMetric"),
  http: $("httpMetric"),
  risk: $("riskMetric"),
  cve: $("cveMetric"),
  log: $("logOutput"),
  findings: $("findingsTable"),
  tools: $("toolsTable"),
  files: $("filesList"),
  history: $("scanHistory"),
  scheduleForm: $("scheduleForm"),
  scheduleId: $("scheduleIdInput"),
  scheduleName: $("scheduleNameInput"),
  scheduleTarget: $("scheduleTargetInput"),
  scheduleMode: $("scheduleModeSelect"),
  scheduleProfile: $("scheduleProfileSelect"),
  scheduleInterval: $("scheduleIntervalInput"),
  scheduleTopPorts: $("scheduleTopPortsInput"),
  schedulePorts: $("schedulePortsInput"),
  scheduleSeverity: $("scheduleSeveritySelect"),
  scheduleTags: $("scheduleTagsInput"),
  scheduleTemplates: $("scheduleTemplatesInput"),
  scheduleEnabled: $("scheduleEnabledInput"),
  scheduleDryRun: $("scheduleDryRunInput"),
  scheduleJsonOutput: $("scheduleJsonOutputInput"),
  scheduleError: $("scheduleError"),
  clearScheduleForm: $("clearScheduleForm"),
  schedulesTable: $("schedulesTable"),
  findingSeverityFilter: $("findingSeverityFilter"),
  findingTargetFilter: $("findingTargetFilter"),
  findingTextFilter: $("findingTextFilter"),
  allFindingsTable: $("allFindingsTable"),
  assetsTable: $("assetsTable"),
  reportsTable: $("reportsTable"),
  refreshHealth: $("refreshHealth"),
  storageStatus: $("storageStatus"),
  toolStatus: $("toolStatus"),
  platformStatus: $("platformStatus"),
  settingsPasswordForm: $("settingsPasswordForm"),
  settingsCurrentPassword: $("settingsCurrentPassword"),
  settingsNewPassword: $("settingsNewPassword"),
  settingsConfirmPassword: $("settingsConfirmPassword"),
  settingsPasswordError: $("settingsPasswordError")
};

function optionValue(input) {
  const value = input.value.trim();
  return value || undefined;
}

function selectedMode() {
  const checked = document.querySelector("input[name='mode']:checked");
  return checked ? checked.value : "chain";
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",
    headers: { "Content-Type": "application/json" },
    ...options
  });
  const text = await response.text();
  const data = text ? JSON.parse(text) : {};
  if (!response.ok) {
    if (response.status === 401) {
      showAuth("login", "Sign in to continue.");
    }
    if (response.status === 403 && data.must_change_password) {
      showAuth("password", "Change the default password before continuing.");
    }
    throw new Error(data.error || `Request failed with ${response.status}`);
  }
  return data;
}

function showAuth(mode, message) {
  els.appShell.classList.add("hidden");
  els.authScreen.classList.remove("hidden");
  els.authMessage.textContent = message || "Sign in to continue.";
  els.loginError.textContent = "";
  els.firstPasswordError.textContent = "";
  els.loginForm.classList.toggle("hidden", mode === "password");
  els.firstPasswordForm.classList.toggle("hidden", mode !== "password");
  stopTimers();
}

function showApp(auth) {
  state.auth = auth;
  els.userBadge.textContent = auth.username || "admin";
  els.authScreen.classList.add("hidden");
  els.appShell.classList.remove("hidden");
  startDataTimer();
}

function stopTimers() {
  if (state.pollTimer) {
    clearInterval(state.pollTimer);
    state.pollTimer = null;
  }
  if (state.dataTimer) {
    clearInterval(state.dataTimer);
    state.dataTimer = null;
  }
}

function startDataTimer() {
  if (state.dataTimer) {
    clearInterval(state.dataTimer);
  }
  state.dataTimer = setInterval(loadAppData, 15000);
}

async function boot() {
  try {
    const session = await api("/api/session");
    if (!session.authenticated) {
      showAuth("login", "Sign in to continue.");
      return;
    }
    if (session.must_change_password) {
      showAuth("password", "Change the default password before continuing.");
      return;
    }
    showApp(session);
    await loadAppData();
  } catch (error) {
    showAuth("login", error.message);
  }
}

async function login(event) {
  event.preventDefault();
  els.loginError.textContent = "";
  try {
    const auth = await api("/api/login", {
      method: "POST",
      body: JSON.stringify({
        username: els.loginUsername.value.trim(),
        password: els.loginPassword.value
      })
    });
    if (auth.must_change_password) {
      els.firstCurrentPassword.value = els.loginPassword.value;
      showAuth("password", "Change the default password before continuing.");
      return;
    }
    showApp(auth);
    await loadAppData();
  } catch (error) {
    els.loginError.textContent = error.message;
  }
}

async function changePassword(event, formType) {
  event.preventDefault();
  const isFirst = formType === "first";
  const errorEl = isFirst ? els.firstPasswordError : els.settingsPasswordError;
  const currentEl = isFirst ? els.firstCurrentPassword : els.settingsCurrentPassword;
  const newEl = isFirst ? els.firstNewPassword : els.settingsNewPassword;
  const confirmEl = isFirst ? els.firstConfirmPassword : els.settingsConfirmPassword;
  errorEl.textContent = "";
  try {
    const auth = await api("/api/change-password", {
      method: "POST",
      body: JSON.stringify({
        current_password: currentEl.value,
        new_password: newEl.value,
        confirm_password: confirmEl.value
      })
    });
    currentEl.value = "";
    newEl.value = "";
    confirmEl.value = "";
    showApp(auth);
    await loadAppData();
  } catch (error) {
    errorEl.textContent = error.message;
  }
}

async function logout() {
  try {
    await api("/api/logout", { method: "POST", body: "{}" });
  } catch (_) {
    // The local session is cleared either way.
  }
  state.auth = null;
  state.scans = [];
  state.schedules = [];
  state.overview = {};
  showAuth("login", "Signed out.");
}

async function loadAppData() {
  const [overview, scansData, schedulesData] = await Promise.all([
    api("/api/overview"),
    api("/api/scans"),
    api("/api/schedules")
  ]);
  state.overview = overview || {};
  state.scans = scansData.scans || [];
  state.schedules = schedulesData.schedules || [];
  state.health = overview.health || {};
  if (!state.currentScanId && state.scans.length) {
    state.currentScanId = state.scans[0].id;
  }
  renderAll();
}

async function refreshHealth() {
  try {
    state.health = await api("/api/health");
    renderHealth();
  } catch (error) {
    els.environment.textContent = error.message;
  }
}

function scanPayload() {
  return {
    target: els.target.value.trim(),
    mode: selectedMode(),
    profile: els.profile.value,
    dry_run: els.dryRun.checked,
    json_output: els.jsonOutput.checked,
    options: {
      ports: optionValue(els.ports),
      top_ports: els.topPorts.value,
      timeout: els.timeout.value,
      severity: optionValue(els.severity),
      tags: optionValue(els.tags),
      templates: optionValue(els.templates)
    }
  };
}

async function startScan(event) {
  event.preventDefault();
  els.formError.textContent = "";
  const button = els.form.querySelector(".primary-button");
  button.disabled = true;
  try {
    const scan = await api("/api/scans", {
      method: "POST",
      body: JSON.stringify(scanPayload())
    });
    state.currentScanId = scan.id;
    renderScan(scan);
    await loadAppData();
    startPolling();
    activateView("scan");
  } catch (error) {
    els.formError.textContent = error.message;
  } finally {
    button.disabled = false;
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
    const index = state.scans.findIndex((item) => item.id === scan.id);
    if (index >= 0) {
      state.scans[index] = scan;
    } else {
      state.scans.unshift(scan);
    }
    renderHistory();
    if (!["queued", "running"].includes(scan.status) && state.pollTimer) {
      clearInterval(state.pollTimer);
      state.pollTimer = null;
      await loadAppData();
    }
  } catch (error) {
    els.formError.textContent = error.message;
  }
}

function schedulePayload() {
  return {
    name: els.scheduleName.value.trim(),
    target: els.scheduleTarget.value.trim(),
    mode: els.scheduleMode.value,
    profile: els.scheduleProfile.value,
    interval_hours: Number(els.scheduleInterval.value || 24),
    enabled: els.scheduleEnabled.checked,
    dry_run: els.scheduleDryRun.checked,
    json_output: els.scheduleJsonOutput.checked,
    options: {
      ports: optionValue(els.schedulePorts),
      top_ports: els.scheduleTopPorts.value,
      severity: optionValue(els.scheduleSeverity),
      tags: optionValue(els.scheduleTags),
      templates: optionValue(els.scheduleTemplates)
    }
  };
}

async function saveSchedule(event) {
  event.preventDefault();
  els.scheduleError.textContent = "";
  const id = els.scheduleId.value;
  const method = id ? "PATCH" : "POST";
  const path = id ? `/api/schedules/${id}` : "/api/schedules";
  try {
    await api(path, {
      method,
      body: JSON.stringify(schedulePayload())
    });
    clearScheduleForm();
    await loadAppData();
  } catch (error) {
    els.scheduleError.textContent = error.message;
  }
}

function clearScheduleForm() {
  els.scheduleId.value = "";
  els.scheduleName.value = "";
  els.scheduleTarget.value = "";
  els.scheduleMode.value = "chain";
  els.scheduleProfile.value = "default";
  els.scheduleInterval.value = "24";
  els.scheduleTopPorts.value = "1000";
  els.schedulePorts.value = "";
  els.scheduleSeverity.value = "";
  els.scheduleTags.value = "";
  els.scheduleTemplates.value = "";
  els.scheduleEnabled.checked = true;
  els.scheduleDryRun.checked = false;
  els.scheduleJsonOutput.checked = true;
  els.scheduleError.textContent = "";
}

function editSchedule(schedule) {
  els.scheduleId.value = schedule.id || "";
  els.scheduleName.value = schedule.name || "";
  els.scheduleTarget.value = schedule.target || "";
  els.scheduleMode.value = schedule.mode || "chain";
  els.scheduleProfile.value = schedule.profile || "default";
  els.scheduleInterval.value = schedule.interval_hours || 24;
  const options = schedule.options || {};
  els.scheduleTopPorts.value = options.top_ports || "1000";
  els.schedulePorts.value = options.ports || "";
  els.scheduleSeverity.value = options.severity || "";
  els.scheduleTags.value = options.tags || "";
  els.scheduleTemplates.value = options.templates || "";
  els.scheduleEnabled.checked = Boolean(schedule.enabled);
  els.scheduleDryRun.checked = Boolean(schedule.dry_run);
  els.scheduleJsonOutput.checked = Boolean(schedule.json_output);
  activateView("schedules");
}

async function runSchedule(id) {
  try {
    const data = await api(`/api/schedules/${id}/run`, { method: "POST", body: "{}" });
    if (data.scan && data.scan.id) {
      state.currentScanId = data.scan.id;
      renderScan(data.scan);
      startPolling();
      activateView("scan");
    }
    await loadAppData();
  } catch (error) {
    els.scheduleError.textContent = error.message;
  }
}

async function deleteSchedule(id) {
  try {
    await api(`/api/schedules/${id}`, { method: "DELETE" });
    await loadAppData();
  } catch (error) {
    els.scheduleError.textContent = error.message;
  }
}

async function toggleSchedule(schedule) {
  try {
    await api(`/api/schedules/${schedule.id}`, {
      method: "PATCH",
      body: JSON.stringify({ enabled: !schedule.enabled })
    });
    await loadAppData();
  } catch (error) {
    els.scheduleError.textContent = error.message;
  }
}

function renderAll() {
  renderHealth();
  renderDashboard();
  renderHistory();
  renderSchedules();
  renderAllFindings();
  renderAssets();
  renderReports();
  const scan = state.scans.find((item) => item.id === state.currentScanId);
  if (scan) {
    renderScan(scan);
  }
}

function renderHealth() {
  const health = state.health || {};
  const tools = health.tools || {};
  const storage = health.storage || {};
  const toolText = Object.entries(tools)
    .map(([tool, info]) => `${tool}: ${info.available === "yes" ? "ok" : "missing"}`)
    .join(" | ");
  const storageText = storage.backend
    ? `storage: ${storage.backend}${storage.available === "yes" ? "" : " unavailable"}`
    : "storage: unknown";
  els.environment.textContent = `${health.platform || "unknown"}; ${toolText || "tools: unknown"}; ${storageText}`;
  els.dashboardStorage.textContent = storage.backend || "Storage";
  els.dashboardStorage.className = `state-badge ${storage.available || "idle"}`;
  renderStatusList(els.storageStatus, [
    ["Backend", storage.backend || "unknown"],
    ["Available", storage.available || "unknown"],
    ["Detail", storage.detail || "N/A"],
    ["Keyspace", storage.keyspace || "N/A"],
    ["History File", storage.path || "N/A"],
    ["Schedules File", storage.schedule_path || "N/A"]
  ]);
  renderStatusList(els.platformStatus, [
    ["Platform", health.platform || "unknown"],
    ["Can Run Scans", health.can_run_scans ? "yes" : "no"],
    ["Missing Tools", (health.missing_tools || []).join(", ") || "none"]
  ]);
  const toolRows = Object.entries(tools).map(([tool, info]) => [tool, info.available || "unknown", info.detail || ""]);
  renderStatusList(els.toolStatus, toolRows.length ? toolRows : [["Tools", "unknown", ""]]);
}

function renderStatusList(container, rows) {
  container.replaceChildren();
  rows.forEach((row) => {
    const item = document.createElement("div");
    item.className = "status-row";
    item.textContent = row[0];
    const value = document.createElement("span");
    value.textContent = row.slice(1).filter(Boolean).join(" | ");
    item.appendChild(value);
    container.appendChild(item);
  });
}

function renderDashboard() {
  const overview = state.overview || {};
  const metrics = overview.metrics || {};
  els.totalScansMetric.textContent = metrics.total_scans || 0;
  els.assetMetric.textContent = metrics.total_assets || 0;
  els.totalRiskMetric.textContent = metrics.security_findings || 0;
  els.criticalMetric.textContent = metrics.critical_findings || 0;
  els.activeScheduleMetric.textContent = metrics.active_schedules || 0;
  els.totalHttpMetric.textContent = metrics.http_services || 0;
  renderLatestScan(overview.latest_scan);
  renderFindingRows(els.dashboardFindings, overview.recent_high_findings || [], 4);
  renderDashboardSchedules();
  drawSeverityChart(els.dashboardSeverityChart, overview.severity_counts || {});
  drawHistoryChart(els.dashboardHistoryChart, state.scans);
  drawCategoryChart(els.dashboardCategoryChart, overview.category_counts || {});
}

function renderLatestScan(scan) {
  els.latestScanSummary.replaceChildren();
  if (!scan) {
    els.latestScanSummary.textContent = "No scans yet";
    return;
  }
  const summary = scan.summary || {};
  const title = document.createElement("strong");
  title.textContent = scan.target || "Unknown target";
  els.latestScanSummary.appendChild(title);
  [
    ["Mode", (scan.mode || "chain").toUpperCase()],
    ["Status", scan.status || "unknown"],
    ["Finished", formatTime(scan.finished_at || scan.created_at)],
    ["Findings", summary.security_findings || 0],
    ["Open Ports", summary.open_ports || 0],
    ["HTTP Services", summary.http_services || 0]
  ].forEach(([label, value]) => {
    const row = document.createElement("div");
    row.textContent = `${label}: ${value}`;
    els.latestScanSummary.appendChild(row);
  });
}

function renderDashboardSchedules() {
  els.dashboardSchedules.replaceChildren();
  const rows = state.schedules.filter((item) => item.enabled).slice(0, 8);
  if (!rows.length) {
    emptyTable(els.dashboardSchedules, 4, "No active schedules");
    return;
  }
  rows.forEach((schedule) => {
    addRow(els.dashboardSchedules, [
      schedule.name || "Schedule",
      schedule.target || "N/A",
      `${schedule.interval_hours || 1}h`,
      formatTime(schedule.next_run_at)
    ]);
  });
}

function renderScan(scan) {
  const summary = scan.summary || {};
  els.scanTitle.textContent = scan.target ? `${(scan.mode || "chain").toUpperCase()} - ${scan.target}` : "No scan selected";
  els.scanSubtitle.textContent = scan.error || scan.output_dir || scan.started_at || "Ready";
  els.scanState.textContent = scan.status || "Idle";
  els.scanState.className = `state-badge ${scan.status || "idle"}`;
  els.openPorts.textContent = summary.open_ports || 0;
  els.http.textContent = summary.http_services || 0;
  els.risk.textContent = summary.security_findings || 0;
  els.cve.textContent = summary.cve_findings || (summary.chart_data || {}).cve_findings || 0;
  els.log.textContent = (scan.lines || []).join("\n");
  els.log.scrollTop = els.log.scrollHeight;
  renderScanFindings(summary.findings || [], summary);
  renderTools(scan.results || []);
  renderFiles(scan);
}

function surfaceResultRows(summary) {
  const rows = [];
  (summary.open_port_targets || []).forEach((target) => {
    rows.push({ severity: "surface", category: "Open TCP Service", name: "Reachable port", cve: "N/A", matched_at: target });
  });
  (summary.http_urls || []).forEach((url) => {
    rows.push({ severity: "surface", category: "HTTP Service", name: "Reachable web service", cve: "N/A", matched_at: url });
  });
  return rows;
}

function renderScanFindings(findings, summary = {}) {
  els.findings.replaceChildren();
  const rows = [...surfaceResultRows(summary), ...findings];
  if (!rows.length) {
    emptyTable(els.findings, 5, "No results");
    return;
  }
  rows.forEach((finding) => {
    addRow(els.findings, ["severity", "category", "name", "cve", "matched_at"].map((key) => {
      const value = Array.isArray(finding[key]) ? finding[key].join(", ") : finding[key];
      return value || "N/A";
    }), { severityIndex: 0 });
  });
}

function renderTools(results) {
  els.tools.replaceChildren();
  if (!results.length) {
    emptyTable(els.tools, 5, "No tool runs");
    return;
  }
  results.forEach((result) => {
    const status = result.success ? "ok" : "failed";
    addRow(els.tools, [
      result.tool || "N/A",
      status,
      result.output_file || "N/A",
      (result.command_preview || []).join(" "),
      result.error || `${result.output_lines || 0} lines`
    ], { statusIndex: 1, status });
  });
}

function renderFiles(scan) {
  els.files.replaceChildren();
  const rows = [];
  if (scan.output_dir) {
    rows.push(["Output directory", scan.output_dir]);
  }
  const reportFile = scan.report_file || (scan.summary || {}).report_file;
  if (reportFile) {
    rows.push(["Vulnerability report", reportFile]);
  }
  (scan.results || []).forEach((result) => {
    if (result.output_file) {
      rows.push([`${result.tool} output`, result.output_file]);
    }
  });
  if (!rows.length) {
    els.files.textContent = "No files";
    return;
  }
  rows.forEach(([label, value]) => {
    const row = document.createElement("div");
    row.className = "file-row";
    row.textContent = label;
    const detail = document.createElement("span");
    detail.textContent = value;
    row.appendChild(detail);
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
    row.textContent = `${(scan.mode || "chain").toUpperCase()} - ${scan.target || "target"}`;
    const detail = document.createElement("span");
    detail.textContent = `${scan.status || "unknown"} | ${formatTime(scan.created_at)}`;
    row.appendChild(detail);
    row.addEventListener("click", () => {
      state.currentScanId = scan.id;
      renderScan(scan);
      if (["queued", "running"].includes(scan.status)) {
        startPolling();
      }
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

function renderSchedules() {
  els.schedulesTable.replaceChildren();
  if (!state.schedules.length) {
    emptyTable(els.schedulesTable, 7, "No schedules");
    return;
  }
  state.schedules.forEach((schedule) => {
    const row = document.createElement("tr");
    [
      schedule.name || "Schedule",
      schedule.target || "N/A",
      (schedule.mode || "chain").toUpperCase(),
      `${schedule.interval_hours || 1}h`,
      schedule.enabled ? formatTime(schedule.next_run_at) : "Disabled",
      schedule.last_status || (schedule.enabled ? "waiting" : "disabled")
    ].forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      if (index === 5) {
        cell.className = `tool-status ${value === "failed" ? "failed" : "ok"}`;
      }
      row.appendChild(cell);
    });
    const actions = document.createElement("td");
    actions.className = "action-row";
    actions.appendChild(actionButton("Run", () => runSchedule(schedule.id)));
    actions.appendChild(actionButton("Edit", () => editSchedule(schedule)));
    actions.appendChild(actionButton(schedule.enabled ? "Disable" : "Enable", () => toggleSchedule(schedule)));
    actions.appendChild(actionButton("Delete", () => deleteSchedule(schedule.id), "danger-button"));
    row.appendChild(actions);
    els.schedulesTable.appendChild(row);
  });
}

function renderAllFindings() {
  const severity = els.findingSeverityFilter.value;
  const target = els.findingTargetFilter.value.trim().toLowerCase();
  const text = els.findingTextFilter.value.trim().toLowerCase();
  let rows = (state.overview.findings || []).slice();
  if (severity) {
    rows = rows.filter((item) => String(item.severity || "").toLowerCase() === severity);
  }
  if (target) {
    rows = rows.filter((item) => String(item.target || "").toLowerCase().includes(target));
  }
  if (text) {
    rows = rows.filter((item) => ["name", "category", "cve", "matched_at"].some((key) => String(item[key] || "").toLowerCase().includes(text)));
  }
  renderFindingRows(els.allFindingsTable, rows, 6);
}

function renderFindingRows(tbody, findings, colspan) {
  tbody.replaceChildren();
  if (!findings.length) {
    emptyTable(tbody, colspan, "No findings");
    return;
  }
  findings.forEach((finding) => {
    const values = colspan === 4
      ? [finding.severity, finding.name, finding.target, finding.cve]
      : [finding.severity, finding.name, finding.category, finding.cve, finding.target, shortId(finding.scan_id)];
    addRow(tbody, values.map((value) => value || "N/A"), { severityIndex: 0 });
  });
}

function renderAssets() {
  els.assetsTable.replaceChildren();
  const assets = state.overview.assets || [];
  if (!assets.length) {
    emptyTable(els.assetsTable, 8, "No assets");
    return;
  }
  assets.forEach((asset) => {
    addRow(els.assetsTable, [
      asset.target,
      formatTime(asset.last_scan_at),
      asset.last_status || "unknown",
      asset.open_ports || 0,
      asset.http_services || 0,
      asset.security_findings || 0,
      signedNumber(asset.finding_delta || 0),
      asset.scan_count || 0
    ]);
  });
}

function renderReports() {
  els.reportsTable.replaceChildren();
  if (!state.scans.length) {
    emptyTable(els.reportsTable, 6, "No reports");
    return;
  }
  state.scans.forEach((scan) => {
    const report = scan.report_file || (scan.summary || {}).report_file || "N/A";
    const artifacts = [
      scan.output_dir,
      ...(scan.results || []).map((result) => result.output_file).filter(Boolean)
    ].filter(Boolean).join(", ") || "N/A";
    addRow(els.reportsTable, [
      scan.target || "N/A",
      (scan.mode || "chain").toUpperCase(),
      scan.status || "unknown",
      formatTime(scan.finished_at || scan.created_at),
      report,
      artifacts
    ]);
  });
}

function actionButton(label, handler, className = "small-button") {
  const button = document.createElement("button");
  button.type = "button";
  button.className = className;
  button.textContent = label;
  button.addEventListener("click", handler);
  return button;
}

function addRow(tbody, values, options = {}) {
  const row = document.createElement("tr");
  values.forEach((value, index) => {
    const cell = document.createElement("td");
    cell.textContent = value == null || value === "" ? "N/A" : String(value);
    if (index === options.severityIndex) {
      cell.className = `severity ${String(value || "unknown").toLowerCase()}`;
    }
    if (index === options.statusIndex) {
      cell.className = `tool-status ${options.status || value}`;
    }
    row.appendChild(cell);
  });
  tbody.appendChild(row);
}

function emptyTable(tbody, colspan, message) {
  const row = document.createElement("tr");
  const cell = document.createElement("td");
  cell.colSpan = colspan;
  cell.textContent = message;
  row.appendChild(cell);
  tbody.appendChild(row);
}

function canvasContext(canvas) {
  const ratio = window.devicePixelRatio || 1;
  const width = Math.max(280, Math.floor(canvas.clientWidth || 320));
  const height = Math.max(180, Math.floor(canvas.clientHeight || 220));
  canvas.width = width * ratio;
  canvas.height = height * ratio;
  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);
  return { ctx, width, height };
}

function drawSeverityChart(canvas, counts) {
  const labels = ["critical", "high", "medium", "low", "info"];
  const values = labels.map((label) => Number(counts[label] || 0));
  const { ctx, width, height } = canvasContext(canvas);
  const maxValue = Math.max(1, ...values);
  const chartTop = 18;
  const chartBottom = height - 34;
  const barWidth = Math.max(22, (width - 50) / labels.length - 14);
  ctx.font = "12px Segoe UI, Arial";
  labels.forEach((label, index) => {
    const x = 34 + index * ((width - 50) / labels.length);
    const barHeight = ((chartBottom - chartTop) * values[index]) / maxValue;
    ctx.fillStyle = severityColors[label];
    ctx.fillRect(x, chartBottom - barHeight, barWidth, barHeight);
    ctx.fillStyle = "#172033";
    ctx.fillText(String(values[index]), x, chartBottom - barHeight - 6);
    ctx.fillStyle = "#65728a";
    ctx.fillText(label, x, height - 12);
  });
}

function drawCategoryChart(canvas, counts) {
  const entries = Object.entries(counts || {})
    .map(([label, value]) => [label, Number(value || 0)])
    .filter(([, value]) => value > 0)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6);
  const { ctx, width } = canvasContext(canvas);
  const padding = { left: 118, right: 18, top: 20 };
  const chartWidth = width - padding.left - padding.right;
  const maxValue = Math.max(1, ...entries.map((entry) => entry[1]));
  ctx.font = "12px Segoe UI, Arial";
  if (!entries.length) {
    ctx.fillStyle = "#65728a";
    ctx.fillText("No finding categories yet", 18, 48);
    return;
  }
  entries.forEach(([label, value], index) => {
    const y = padding.top + index * 28;
    const barWidth = Math.max(4, (chartWidth * value) / maxValue);
    ctx.fillStyle = "#65728a";
    ctx.fillText(label.length > 18 ? `${label.slice(0, 17)}...` : label, 8, y + 14);
    ctx.fillStyle = index % 2 === 0 ? "#245fc8" : "#0b8587";
    ctx.fillRect(padding.left, y, barWidth, 16);
    ctx.fillStyle = "#172033";
    ctx.fillText(String(value), padding.left + barWidth + 8, y + 13);
  });
}

function drawHistoryChart(canvas, scans) {
  const rows = (scans || []).filter((scan) => scan.summary && !scan.dry_run).slice().reverse().slice(-12);
  const { ctx, width, height } = canvasContext(canvas);
  const padding = { left: 34, right: 14, top: 22, bottom: 34 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const riskValues = rows.map((scan) => Number((scan.summary || {}).security_findings || 0));
  const portValues = rows.map((scan) => Number((scan.summary || {}).open_ports || 0));
  const maxValue = Math.max(1, ...riskValues, ...portValues);

  ctx.strokeStyle = "#d9e0ea";
  ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(padding.left, padding.top);
  ctx.lineTo(padding.left, padding.top + chartHeight);
  ctx.lineTo(padding.left + chartWidth, padding.top + chartHeight);
  ctx.stroke();

  if (!rows.length) {
    ctx.fillStyle = "#65728a";
    ctx.font = "13px Segoe UI, Arial";
    ctx.fillText("No stored scans", padding.left + 8, padding.top + 28);
    return;
  }

  function point(index, value) {
    const x = rows.length === 1 ? padding.left + chartWidth / 2 : padding.left + (chartWidth * index) / (rows.length - 1);
    const y = padding.top + chartHeight - (chartHeight * value) / maxValue;
    return { x, y };
  }

  function drawLine(values, color) {
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    values.forEach((value, index) => {
      const p = point(index, value);
      if (index === 0) {
        ctx.moveTo(p.x, p.y);
      } else {
        ctx.lineTo(p.x, p.y);
      }
    });
    ctx.stroke();
    ctx.fillStyle = color;
    values.forEach((value, index) => {
      const p = point(index, value);
      ctx.beginPath();
      ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
      ctx.fill();
    });
  }

  drawLine(portValues, "#245fc8");
  drawLine(riskValues, "#b83232");
  ctx.font = "12px Segoe UI, Arial";
  ctx.fillStyle = "#245fc8";
  ctx.fillText("Ports", padding.left + 4, 16);
  ctx.fillStyle = "#b83232";
  ctx.fillText("Findings", padding.left + 58, 16);
  ctx.fillStyle = "#65728a";
  ctx.fillText(String(maxValue), 6, padding.top + 4);
  ctx.fillText("0", 18, padding.top + chartHeight);
}

function activateView(name) {
  $$(".console-tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.view === name));
  $$(".view").forEach((view) => view.classList.toggle("active", view.id === `${name}View`));
  if (name === "findings") {
    renderAllFindings();
  }
}

function formatTime(value) {
  if (!value) {
    return "N/A";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleString();
}

function shortId(value) {
  return value ? String(value).slice(0, 8) : "N/A";
}

function signedNumber(value) {
  const number = Number(value || 0);
  return number > 0 ? `+${number}` : String(number);
}

$$(".console-tab").forEach((tab) => {
  tab.addEventListener("click", () => activateView(tab.dataset.view));
});

$$(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    $$(".tab").forEach((item) => item.classList.remove("active"));
    $$(".tab-panel").forEach((item) => item.classList.remove("active"));
    tab.classList.add("active");
    $(`${tab.dataset.tab}Tab`).classList.add("active");
  });
});

els.loginForm.addEventListener("submit", login);
els.firstPasswordForm.addEventListener("submit", (event) => changePassword(event, "first"));
els.settingsPasswordForm.addEventListener("submit", (event) => changePassword(event, "settings"));
els.logoutButton.addEventListener("click", logout);
els.refreshAll.addEventListener("click", loadAppData);
els.refreshHealth.addEventListener("click", refreshHealth);
els.form.addEventListener("submit", startScan);
els.scheduleForm.addEventListener("submit", saveSchedule);
els.clearScheduleForm.addEventListener("click", clearScheduleForm);
[els.findingSeverityFilter, els.findingTargetFilter, els.findingTextFilter].forEach((input) => {
  input.addEventListener("input", renderAllFindings);
  input.addEventListener("change", renderAllFindings);
});
window.addEventListener("resize", () => {
  renderDashboard();
});

boot();
