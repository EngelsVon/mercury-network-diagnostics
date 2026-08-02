"use strict";
let csrf = "";
let activeTask = null;
const state = document.querySelector("#task-state");
const output = document.querySelector("#task-output");
const historyOutput = document.querySelector("#history-output");
const statusOutput = document.querySelector("#status-output");
const taskContext = document.querySelector("#task-context");
const taskDescriptions = {
  diagnose: "Check one selected private endpoint.",
  discover_passive: "Read local network facts without probes.",
  discover: "Map one authorized private CIDR with a fixed profile.",
  trace: "Collect bounded route evidence for one private target.",
  paired: "Run the configured reciprocal peer diagnostic.",
  mapping: "Map selected private ranges with bounded rate and duration.",
  coverage: "Test configured receiver profiles in both directions.",
};
function field(name) { return document.querySelector(name).value.trim(); }
function csv(name) { return field(name) ? field(name).split(",").map((value) => value.trim()).filter(Boolean) : []; }
function integer(name, fallback) { const value = Number(field(name)); return Number.isInteger(value) ? value : fallback; }
function syncTaskForm() {
  const kind = field("#kind");
  taskContext.textContent = taskDescriptions[kind] || "Choose a task to show its inputs.";
  for (const group of document.querySelectorAll("[data-kinds]")) {
    const kinds = group.dataset.kinds.split(",");
    group.hidden = !kinds.includes(kind);
  }
}
async function request(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error ? value.error.message : "request failed");
  return value;
}
function taskHeaders() { return { "Content-Type": "application/json", "X-Mercury-CSRF": csrf }; }
function cell(row, value) { const element = document.createElement("td"); element.textContent = value; row.appendChild(element); }
function listItem(list, value) { const item = document.createElement("li"); item.textContent = value; list.appendChild(item); }
function renderCoverage(result) {
  const section = document.querySelector("#coverage-result");
  const body = document.querySelector("#coverage-result-body");
  const candidates = document.querySelector("#candidate-carriers");
  const gaps = document.querySelector("#coverage-gaps");
  body.replaceChildren(); candidates.replaceChildren(); gaps.replaceChildren();
  const profiles = Array.isArray(result.requested_config?.coverage_profiles) ? result.requested_config.coverage_profiles : [];
  const observations = Array.isArray(result.observations) ? result.observations : [];
  if (!profiles.length) { section.hidden = true; return; }
  section.hidden = false;
  for (const profile of profiles) {
    const matching = observations.filter((item) => item.detail?.coverage_profile === profile || item.detail?.native_profile === profile);
    const directions = result.task_kind === "coverage" ? ["outbound", "reverse"] : ["outbound"];
    for (const direction of directions) {
      const evidence = matching.filter((item) => item.direction === direction || item.detail?.coverage_role === direction);
      const row = document.createElement("tr");
      const first = evidence[0];
      const port = first?.detail?.receiver_destination_port ?? first?.detail?.port ?? "—";
      const outcome = evidence.length ? evidence.map((item) => item.disposition).join(", ") : "coverage gap";
      cell(row, profile); cell(row, direction); cell(row, String(port)); cell(row, outcome);
      cell(row, evidence.map((item) => item.evidence_kind).join(", ") || "no recorded evidence");
      cell(row, evidence.map((item) => item.source).filter(Boolean).join(", ") || "not observed");
      body.appendChild(row);
      if (!evidence.length) listItem(gaps, `${profile} ${direction}: no recorded evidence in this assessment.`);
      if (evidence.some((item) => item.disposition === "positive")) listItem(candidates, `${profile} ${direction}: positive evidence was recorded.`);
    }
  }
  if (!candidates.children.length) listItem(candidates, "No positive candidate carrier was recorded in this finite assessment.");
  if (!gaps.children.length) listItem(gaps, "No profile-direction row was empty; inspect unavailable and inconclusive evidence above.");
}
async function start(body, presentation = "task") {
  const value = await request("/api/tasks", { method: "POST", headers: taskHeaders(), body: JSON.stringify(body) });
  activeTask = { id: value.task_id, presentation };
  document.querySelector("#cancel-button").disabled = false;
  poll();
}
async function poll() {
  if (!activeTask) return;
  try {
    const currentTask = activeTask;
    const value = await request(`/api/tasks/${currentTask.id}`);
    state.textContent = `Task ${value.state}`;
    if (value.result || value.error) {
      const destination = currentTask.presentation === "status" ? statusOutput : output;
      destination.textContent = JSON.stringify(value.result || value.error, null, 2);
      if (value.result) renderCoverage(value.result);
      activeTask = null;
      document.querySelector("#cancel-button").disabled = true;
      return;
    }
    setTimeout(poll, 500);
  } catch (error) {
    state.textContent = error.message;
    activeTask = null;
  }
}
document.addEventListener("DOMContentLoaded", async () => {
  try { csrf = (await request("/api/bootstrap")).csrf; } catch (error) { state.textContent = error.message; }
  syncTaskForm();
  document.querySelector("#kind").addEventListener("change", syncTaskForm);
  document.querySelector("#status-button").addEventListener("click", async () => {
    try { await start({ kind: "status" }, "status"); } catch (error) { statusOutput.textContent = error.message; }
  });
  document.querySelector("#task-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const kind = field("#kind");
    const target = field("#target");
    const scope = field("#scope");
    const profile = field("#profile");
    const authorized = document.querySelector("#authorized").checked;
    let body = { kind, authorized };
    if (kind === "diagnose") body = { ...body, profile, targets: target ? [target] : [] };
    if (kind === "discover_passive") body = { kind };
    if (kind === "discover") {
      const ports = field("#ports") ? field("#ports").split(",").map((value) => Number(value.trim())) : [];
      const confirmation = field("#confirmation");
      body = { ...body, network: target, scope, profile, ports, confirmations: confirmation ? [confirmation] : [] };
    }
    if (kind === "trace") body = { ...body, target, scope };
    if (kind === "paired") body = { ...body, config_path: field("#config-path"), identity: field("#identity"), address: target };
    if (kind === "mapping") body = {
      ...body, cidrs: csv("#ranges"), profiles: csv("#coverage-profiles"),
      ports: csv("#ports").map(Number), rate: integer("#rate", 10),
      concurrency: integer("#concurrency", 1), duration_s: integer("#duration", 0),
    };
    if (kind === "coverage") body = {
      ...body, config_path: field("#config-path"), identity: field("#identity"), address: target,
      profiles: csv("#coverage-profiles"), local_network: field("#local-network") || null,
      peer_network: field("#peer-network") || null,
    };
    try { await start(body); } catch (error) { state.textContent = error.message; }
  });
  document.querySelector("#cancel-button").addEventListener("click", async () => {
    if (!activeTask) return;
    try { await request(`/api/tasks/${activeTask.id}`, { method: "DELETE", headers: { "X-Mercury-CSRF": csrf } }); } catch (error) { state.textContent = error.message; }
  });
  document.querySelector("#history-button").addEventListener("click", async () => {
    try { historyOutput.textContent = JSON.stringify(await request("/api/history"), null, 2); } catch (error) { historyOutput.textContent = error.message; }
  });
  document.querySelector("#compare-button").addEventListener("click", async () => {
    const left = field("#compare-left");
    const right = field("#compare-right");
    try { historyOutput.textContent = JSON.stringify(await request(`/api/history/compare?left=${encodeURIComponent(left)}&right=${encodeURIComponent(right)}`), null, 2); } catch (error) { historyOutput.textContent = error.message; }
  });
  document.querySelector("#report-button").addEventListener("click", () => {
    const task = field("#report-task");
    if (task) window.open(`/api/history/${encodeURIComponent(task)}/report?format=html`, "_blank", "noopener");
  });
});
