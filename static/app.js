"use strict";

const $ = (selector) => document.querySelector(selector);
const state = { wordlistText: "", hashFileName: "", inputFormat: "txt", taskId: null, eventSource: null, theme: "dark", lastSnapshot: null, targetMetadata: {} };
const MAX_HASH_BYTES = 512 * 1024;
const MAX_WORDLIST_BYTES = 2 * 1024 * 1024;

function logActivity(message) {
  const item = document.createElement("li");
  const time = document.createElement("time");
  const content = document.createElement("span");
  time.textContent = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  content.textContent = message;
  item.append(time, content);
  $("#activity-log").prepend(item);
}

function showError(message) {
  const box = $("#form-error");
  box.textContent = message;
  box.hidden = !message;
}

async function readFile(file, limit) {
  if (!file) return "";
  if (file.size > limit) {
    const maximum = limit < 1024 * 1024 ? `${Math.floor(limit / 1024)} KiB` : `${limit / (1024 * 1024)} MiB`;
    throw new Error(`File exceeds the ${maximum} limit.`);
  }
  return file.text();
}

function parseCsvRows(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;
  for (let index = 0; index < text.length; index += 1) {
    const char = text[index];
    if (quoted && char === '"' && text[index + 1] === '"') {
      field += '"'; index += 1;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (!quoted && char === ",") {
      row.push(field); field = "";
    } else if (!quoted && (char === "\n" || char === "\r")) {
      row.push(field); rows.push(row); row = []; field = "";
      if (char === "\r" && text[index + 1] === "\n") index += 1;
    } else {
      field += char;
    }
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows;
}

function inputHashValues(text, format) {
  if (format === "txt") return text.split(/\r?\n/).map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
  const rows = parseCsvRows(text);
  const digestIndex = (rows[0] || []).indexOf("digest");
  if (digestIndex < 0) return [];
  return rows.slice(1).map((row) => (row[digestIndex] || "").trim()).filter(Boolean);
}

function identifyDigest(value) {
  let cleaned = value.trim();
  if (!cleaned) return { label: "Enter a digest to inspect its likely format.", valid: false, empty: true };
  if ($("#input-format")?.value === "csv") {
    const rows = cleaned.split(/\r?\n/);
    const headers = (rows[0] || "").split(",").map((cell) => cell.trim().replace(/^"|"$/g, ""));
    const digestIndex = headers.indexOf("digest");
    if (digestIndex < 0) return { label: 'CSV needs an exact "digest" header.', valid: false };
    const firstRow = (rows[1] || "").split(",");
    cleaned = (firstRow[digestIndex] || "").trim().replace(/^"|"$/g, "");
  }
  if (!cleaned) return { label: "Enter a digest to inspect its likely format.", valid: false, empty: true };
  if (/^\$2[aby]\$/.test(cleaned)) return { label: "bcrypt modular-crypt encoding · recognized; bounded cost verification", valid: true };
  if (/^\$argon2(id|i|d)\$/.test(cleaned)) return { label: "Argon2 PHC encoding · parameters will be checked against local limits", valid: true };
  if (/^\$scrypt\$/.test(cleaned)) return { label: "scrypt PHC subset · standard-base64 parameters", valid: true };
  if (/^pbkdf2_sha256\$/.test(cleaned)) return { label: "Django PBKDF2-SHA256 encoding · iteration count bounded", valid: true };
  const custom = cleaned.match(/^(md5|ntlm|sha-1|sha1|sha-224|sha224|sha-256|sha256|sha-384|sha384|sha-512|sha512|sha3-224|sha3-256|sha3-384|sha3-512)\$[^$]*\$([0-9a-f]+)$/i);
  const digest = custom ? custom[2] : cleaned;
  if (!/^[0-9a-f]+$/i.test(digest)) return { label: "Not a recognized supported encoding or hexadecimal digest.", valid: false };
  const candidates = ({ 32: ["MD5", "NTLM (explicit only)"], 40: ["SHA-1"], 56: ["SHA-224", "SHA3-224"],
    64: ["SHA-256", "SHA3-256"], 96: ["SHA-384", "SHA3-384"], 128: ["SHA-512", "SHA3-512"] })[digest.length];
  if (!candidates) return { label: `Unsupported raw hexadecimal length (${digest.length}).`, valid: false };
  if (candidates.length > 1) return { label: `Ambiguous ${digest.length}-hex raw digest (${candidates.join(" / ")}); select an algorithm manually.`, valid: false };
  return { label: `${custom ? "Explicitly salted " : "Likely "}${candidates[0]} raw hex · length is only a heuristic`, valid: true };
}

function updateDetection() {
  const inputText = $("#hash-input").value;
  const csvMode = $("#input-format").value === "csv";
  const first = csvMode ? inputText : inputText.split(/\r?\n/).find((line) => line.trim() && !line.trim().startsWith("#")) || "";
  const info = identifyDigest(first);
  const selectedAlgorithm = $("#algorithm").value;
  const firstDigest = csvMode
    ? (inputText.split(/\r?\n/)[1] || "").split(",")[(inputText.split(/\r?\n/)[0] || "").split(",").indexOf("digest")] || ""
    : first;
  if (firstDigest.trim() && selectedAlgorithm && /^[0-9a-f]+$/i.test(firstDigest.trim())) {
    info.valid = true;
    info.label = `Explicit selection: ${selectedAlgorithm.toUpperCase()} raw hexadecimal digest.`;
  }
  const box = $("#detected-info");
  box.classList.toggle("valid", info.valid);
  box.classList.toggle("invalid", !info.valid && !info.empty);
  box.lastElementChild.textContent = info.label;
}

function updateMethod() {
  const mask = $("#method").value === "mask";
  const manual = $("#method").value === "manual";
  $("#mask-options").hidden = !mask;
  $("#dictionary-options").hidden = mask || manual;
  $("#manual-options").hidden = !manual;
}

function formatDuration(seconds) {
  if (seconds == null || !Number.isFinite(seconds)) return "—";
  if (seconds < 60) return `${Math.ceil(seconds)}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${Math.ceil(seconds % 60)}s`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m`;
}

function paintProgress(data) {
  state.lastSnapshot = data;
  const percent = Math.min(100, Math.max(0, Number(data.progress || 0)));
  $("#progress-percent").textContent = `${percent.toFixed(percent % 1 ? 1 : 0)}%`;
  $("#tested-count").textContent = `${Number(data.tested_count || 0).toLocaleString()} candidates tested${data.total_candidates ? ` / ${Number(data.total_candidates).toLocaleString()}` : ""}`;
  $("#progress-fill").style.width = `${percent}%`;
  $(".progress-track").setAttribute("aria-valuenow", String(percent));
  $("#rate-value").textContent = Number(data.rate || 0) ? `${Number(data.rate).toLocaleString(undefined, { maximumFractionDigits: 1 })}/s` : "—";
  $("#eta-value").textContent = formatDuration(data.eta_seconds);
  $("#elapsed-value").textContent = formatDuration(data.elapsed_seconds) || "0s";
  const badge = $("#state-badge");
  badge.textContent = data.limit_reached && data.state === "completed" ? "LIMIT REACHED" : String(data.state || "idle").toUpperCase();
  badge.className = `state-badge ${data.state || "idle"}`;
  $("#pause-button").disabled = data.state !== "running";
  $("#resume-button").disabled = data.state !== "paused";
  $("#cancel-button").disabled = !["queued", "running", "paused"].includes(data.state);
  $("#start-button").disabled = ["queued", "running", "paused"].includes(data.state);
  if (data.matches) renderMatches(data.matches, data);
  renderTargetStatuses(data.targets || []);
  if (data.state === "completed") logActivity(data.limit_reached ? "Candidate ceiling reached; remaining candidates were not tested." : data.matches?.length ? "Analysis completed with verified match(es)." : "Analysis completed; no candidate matched.");
  if (data.state === "cancelled") logActivity("Analysis stopped.");
  if (data.state === "error") logActivity(`Analysis error: ${data.error || "check configuration"}`);
}

function renderMatches(matches, data) {
  $("#match-count").textContent = `${matches.length} MATCH${matches.length === 1 ? "" : "ES"}`;
  const result = $("#result-content");
  result.replaceChildren();
    if (!matches.length) {
      if (data.state === "completed") showNoMatch(data.limit_reached, data.tested_count, data.total_candidates);
      else if (data.state === "cancelled") showStopped(data.tested_count);
      else if (data.state === "error") showTaskError(data.error);
      else showPendingResults("Analysis in progress");
      return;
    }
  for (const match of matches) {
    const card = document.createElement("div"); card.className = "match-card";
    const top = document.createElement("div"); top.className = "match-top";
    const target = document.createElement("span"); target.textContent = match.target || "Verified digest";
    const algorithm = document.createElement("span"); algorithm.textContent = match.algorithm || "MATCH";
    const value = document.createElement("strong"); value.className = "match-value"; value.textContent = match.candidate;
    top.append(target, algorithm); card.append(top, value); result.append(card);
  }
  $("#export-results").hidden = !(data.targets?.length) || !["completed", "cancelled", "error"].includes(data.state);
}

function renderTargetStatuses(targets) {
  const panel = $("#target-statuses");
  panel.replaceChildren();
  const statusLabels = { pending: "PENDING", matched: "MATCH FOUND", not_matched: "NO MATCH FOUND",
    not_tested_limit: "NOT TESTED · LIMIT", cancelled: "CANCELLED", error: "ERROR", invalid_format: "INVALID FORMAT" };
  for (const target of targets) {
    const row = document.createElement("div"); row.className = "target-status-row";
    const metadata = state.targetMetadata[target.target] || target;
    const title = document.createElement("strong"); title.textContent = `${target.target} · ${target.algorithm} · ${target.format}`;
    const status = document.createElement("span"); status.textContent = target.duplicate_of
      ? `${statusLabels[target.status] || target.status} · duplicate of ${target.duplicate_of}`
      : statusLabels[target.status] || target.status;
    const details = document.createElement("small");
    const hashPreview = metadata.hashPreview || "";
    const hashText = hashPreview ? `Hash: ${hashPreview.length > 72 ? `${hashPreview.slice(0, 69)}…` : hashPreview}` : "Hash: unavailable";
    const parameters = metadata.parameters && Object.keys(metadata.parameters).length ? ` · ${JSON.stringify(metadata.parameters)}` : "";
    const salt = metadata.salt ? ` · salt (${metadata.encoding || "encoded"}): ${metadata.salt}` : " · salt: none / not encoded";
    const lengthUnit = metadata.format === "raw hex" ? "hex characters"
      : metadata.format === "bcrypt" ? "encoding characters"
      : metadata.format === "invalid" ? "input characters" : "digest bytes";
    const confidence = Number.isFinite(metadata.confidence) ? ` · confidence: ${Math.round(metadata.confidence * 100)}%` : "";
    const reasonText = metadata.error || metadata.reason;
    const reason = reasonText ? ` · reason: ${reasonText}` : "";
    details.textContent = `${hashText} · encoding: ${metadata.encoding || "unknown"} · length: ${metadata.length ?? "?"} ${lengthUnit}${salt}${parameters}${confidence}${reason}`;
    row.append(title, status, details); panel.append(row);
  }
}

function exportResults() {
  const snapshot = state.lastSnapshot;
  if (!snapshot) return;
  const matches = new Map((snapshot.matches || []).map((match) => [match.target, match.candidate]));
  const rows = [["target", "algorithm", "format", "status", "verified_candidate"]];
  for (const target of snapshot.targets || []) {
    rows.push([target.target, target.algorithm, target.format, target.status, matches.get(target.target) || ""]);
  }
  const csv = rows.map((row) => row.map((value) => `"${String(value ?? "").replaceAll('"', '""')}"`).join(",")).join("\r\n");
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
  link.download = "hashhunter-results.csv"; link.click(); URL.revokeObjectURL(link.href);
}

function showPendingResults(titleText = "Nothing to report yet") {
  $("#match-count").textContent = "0 MATCHES";
  const result = $("#result-content");
  result.replaceChildren();
  const empty = document.createElement("div"); empty.className = "empty-state";
  const icon = document.createElement("span"); icon.className = "empty-icon"; icon.textContent = "⌁";
  const title = document.createElement("strong"); title.textContent = titleText;
  const p = document.createElement("p"); p.textContent = titleText === "Analysis in progress" ? "Verified matches will appear here only after a candidate matches." : "Start an analysis to see verified matches here. Candidates are shown only after a digest match.";
  empty.append(icon, title, p); result.append(empty);
}

function showNoMatch(limitReached = false, tested = 0, total = 0) {
  const result = $("#result-content");
  result.replaceChildren();
  const empty = document.createElement("div"); empty.className = "empty-state";
  const icon = document.createElement("span"); icon.className = "empty-icon"; icon.textContent = "⌁";
  const title = document.createElement("strong"); title.textContent = limitReached ? "Candidate limit reached" : "No match found";
  const p = document.createElement("p"); p.textContent = limitReached
    ? `No match among ${Number(tested).toLocaleString()} tested candidates; ${Number(total).toLocaleString()} were in the configured search.`
    : "No tested candidate verified against the supplied digest.";
  empty.append(icon, title, p); result.append(empty);
}

function showStopped(tested = 0) {
  const result = $("#result-content");
  result.replaceChildren();
  const empty = document.createElement("div"); empty.className = "empty-state";
  const title = document.createElement("strong"); title.textContent = "Analysis stopped";
  const p = document.createElement("p"); p.textContent = `No match found in ${Number(tested).toLocaleString()} candidates tested before cancellation.`;
  empty.append(title, p); result.append(empty);
}

function showTaskError(message) {
  const result = $("#result-content");
  result.replaceChildren();
  const empty = document.createElement("div"); empty.className = "empty-state";
  const title = document.createElement("strong"); title.textContent = "Analysis could not finish";
  const p = document.createElement("p"); p.textContent = message || "Check the input and configuration, then try again.";
  empty.append(title, p); result.append(empty);
}
function renderSecurity(report) {
  if (!report) return;
  const panel = $("#security-content");
  panel.replaceChildren();
  const heading = document.createElement("h3"); heading.textContent = `${report.algorithm} · ${report.format || "raw hex"} · ${report.digest_length} ${report.digest_unit || "hex characters"}`;
  const weakness = document.createElement("p"); weakness.textContent = report.weakness;
  const strength = document.createElement("p"); strength.textContent = `Candidate strength estimate: ${report.strength_estimate}`;
  const list = document.createElement("ul");
  for (const recommendation of report.recommendations || []) { const li = document.createElement("li"); li.textContent = recommendation; list.append(li); }
  panel.append(heading, weakness, strength, list); panel.hidden = false;
}

async function getJson(url, options) {
  const response = await fetch(url, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = Array.isArray(payload.detail) ? payload.detail.map((item) => item.msg).join(" ") : payload.detail;
    throw new Error(detail || `Request failed (${response.status}).`);
  }
  return payload;
}

async function startAnalysis() {
  showError("");
  const hashText = $("#hash-input").value.trim();
  if (!$("#authorized").checked) return showError("Confirm that you own these hashes or have explicit authorization before starting.");
  if (!hashText) return showError("Paste a hash or load a text file first.");
  if (new Blob([hashText]).size > MAX_HASH_BYTES) return showError("Hash input exceeds the 512 KiB limit.");
  const payload = {
    hash_text: hashText,
    authorized: $("#authorized").checked,
    algorithm: $("#algorithm").value || null,
    input_format: $("#input-format").value,
    salt: $("#salt-input").value,
    salt_position: $("#salt-position").value,
    method: $("#method").value,
    manual_candidate: $("#manual-candidate").value,
    wordlist_text: state.wordlistText,
    include_common: $("#include-common").checked,
    apply_rules: $("#apply-rules").checked,
    max_length: Number($("#max-length").value),
    mask: $("#mask-input").value,
    custom_charset: $("#custom-charset").value,
    candidate_ceiling: Number($("#candidate-ceiling").value)
  };
  $("#start-button").disabled = true;
  try {
    const result = await getJson("/api/tasks", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    state.taskId = result.task_id;
    if (payload.method === "manual") $("#manual-candidate").value = "";
    const hashValues = inputHashValues(payload.hash_text, payload.input_format);
    state.targetMetadata = Object.fromEntries((result.targets || []).map((target, index) =>
      [target.target, { ...target, hashPreview: hashValues[index] || "" }]));
    $("#security-content").hidden = true;
    $("#security-content").replaceChildren();
    showPendingResults();
    for (const report of result.analysis || []) renderSecurity(report);
    paintProgress({ state: result.state, tested_count: 0, progress: 0, matches: [] });
    renderTargetStatuses((result.targets || []).map((target) => ({ ...target, status: target.status || "pending" })));
    if (result.effective_candidate_ceiling < payload.candidate_ceiling) logActivity(`Structured KDF work is capped at ${result.effective_candidate_ceiling} candidates for this task.`);
    logActivity(`Local ${payload.method} analysis started for ${hashText.split(/\r?\n/).filter((line) => line.trim() && !line.trim().startsWith("#")).length} hash(es).`);
    watchTask(result.task_id);
  } catch (error) {
    showError(error.message);
  } finally {
    $("#start-button").disabled = ["QUEUED", "RUNNING", "PAUSED"].includes($("#state-badge").textContent);
  }
}

function watchTask(taskId) {
  if (state.eventSource) state.eventSource.close();
  const source = new EventSource(`/api/tasks/${encodeURIComponent(taskId)}/events`);
  state.eventSource = source;
  source.addEventListener("progress", (event) => {
    const data = JSON.parse(event.data);
    paintProgress(data);
    if (data.state === "completed" && data.matches?.length) {
      // A fresh task snapshot includes the recovery-only strength assessment.
      getJson(`/api/tasks/${encodeURIComponent(taskId)}`).then((snapshot) => {
        if (snapshot.matches?.[0]?.security_report) renderSecurity(snapshot.matches[0].security_report);
      }).catch(() => {});
    }
  });
  source.addEventListener("done", () => source.close());
  source.onerror = () => { if (source.readyState === EventSource.CLOSED) source.close(); };
}

async function control(action) {
  if (!state.taskId) return;
  showError("");
  try {
    const snapshot = await getJson(`/api/tasks/${encodeURIComponent(state.taskId)}/${action}`, { method: "POST" });
    paintProgress(snapshot);
    logActivity(`Analysis ${{ pause: "paused", resume: "resumed", cancel: "stopped" }[action]}.`);
  } catch (error) { showError(error.message); }
}

function resetDashboard() {
  const activeStates = ["QUEUED", "RUNNING", "PAUSED"];
  if (state.taskId && activeStates.includes($("#state-badge").textContent)) {
    fetch(`/api/tasks/${encodeURIComponent(state.taskId)}/cancel`, { method: "POST" }).catch(() => {});
  }
  if (state.eventSource) state.eventSource.close();
  state.eventSource = null; state.taskId = null; state.wordlistText = ""; state.hashFileName = ""; state.inputFormat = "txt"; state.lastSnapshot = null; state.targetMetadata = {};
  $("#hash-input").value = ""; $("#hash-file").value = ""; $("#hash-file-name").textContent = "No file selected";
  $("#input-format").value = "txt"; $("#manual-candidate").value = ""; $("#target-statuses").replaceChildren(); $("#export-results").hidden = true;
  $("#wordlist-file").value = ""; $("#wordlist-file-name").textContent = "Built-in common candidates only";
  $("#salt-input").value = ""; $("#authorized").checked = false; $("#form-error").hidden = true;
  $("#progress-percent").textContent = "0%"; $("#tested-count").textContent = "0 candidates tested";
  $("#progress-fill").style.width = "0%"; $(".progress-track").setAttribute("aria-valuenow", "0");
  $("#rate-value").textContent = "—"; $("#eta-value").textContent = "—"; $("#elapsed-value").textContent = "0s";
  $("#state-badge").textContent = "IDLE"; $("#state-badge").className = "state-badge idle";
  $("#match-count").textContent = "0 MATCHES"; showPendingResults();
  ["#pause-button", "#resume-button", "#cancel-button"].forEach((s) => { $(s).disabled = true; });
  updateDetection(); logActivity("Dashboard cleared; current task stream disconnected.");
}

$("#hash-input").addEventListener("input", updateDetection);
$("#input-format").addEventListener("change", updateDetection);
$("#algorithm").addEventListener("change", updateDetection);
$("#method").addEventListener("change", updateMethod);
$("#theme-toggle").addEventListener("click", () => {
  state.theme = state.theme === "dark" ? "light" : "dark";
  document.documentElement.dataset.theme = state.theme;
  $("#theme-toggle").textContent = state.theme === "dark" ? "☼" : "☾";
});
$("#hash-file").addEventListener("change", async (event) => {
  try { const file = event.target.files[0]; if (!file) return; $("#hash-input").value = await readFile(file, MAX_HASH_BYTES); $("#hash-file-name").textContent = file.name; state.inputFormat = file.name.toLowerCase().endsWith(".csv") ? "csv" : "txt"; $("#input-format").value = state.inputFormat; updateDetection(); logActivity("Hash file loaded into memory."); }
  catch (error) { showError(error.message); event.target.value = ""; }
});
$("#wordlist-file").addEventListener("change", async (event) => {
  try { const file = event.target.files[0]; if (!file) return; state.wordlistText = await readFile(file, MAX_WORDLIST_BYTES); $("#wordlist-file-name").textContent = `${file.name} · ${file.size.toLocaleString()} bytes`; logActivity("Wordlist loaded into memory; it will be consumed line by line."); }
  catch (error) { showError(error.message); event.target.value = ""; state.wordlistText = ""; }
});
$("#start-button").addEventListener("click", startAnalysis);
$("#pause-button").addEventListener("click", () => control("pause"));
$("#resume-button").addEventListener("click", () => control("resume"));
$("#cancel-button").addEventListener("click", () => control("cancel"));
$("#clear-button").addEventListener("click", resetDashboard);
$("#clear-log").addEventListener("click", () => { $("#activity-log").replaceChildren(); logActivity("Activity log cleared."); });
$("#export-results").addEventListener("click", exportResults);
$("#demo-button").addEventListener("click", async () => {
  try { const demo = await getJson("/api/demo-hash", { method: "POST" }); $("#hash-input").value = demo.hash; $("#algorithm").value = demo.algorithm; updateDetection(); logActivity("A local SHA-256 demo hash was generated; use dictionary candidates to explore the workflow."); }
  catch (error) { showError(error.message); }
});
updateMethod(); updateDetection();
