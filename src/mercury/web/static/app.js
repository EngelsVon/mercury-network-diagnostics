"use strict";
let csrf = "";
let activeTask = null;
const state = document.querySelector("#task-state");
const output = document.querySelector("#task-output");
const historyOutput = document.querySelector("#history-output");
function field(name) { return document.querySelector(name).value.trim(); }
async function request(path, options = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...options });
  const value = await response.json();
  if (!response.ok) throw new Error(value.error ? value.error.message : "request failed");
  return value;
}
function taskHeaders() { return { "Content-Type": "application/json", "X-Mercury-CSRF": csrf }; }
async function start(body) {
  const value = await request("/api/tasks", { method: "POST", headers: taskHeaders(), body: JSON.stringify(body) });
  activeTask = value.task_id;
  document.querySelector("#cancel-button").disabled = false;
  poll();
}
async function poll() {
  if (!activeTask) return;
  try {
    const value = await request(`/api/tasks/${activeTask}`);
    state.textContent = `Task ${value.state}`;
    if (value.result || value.error) {
      output.textContent = JSON.stringify(value.result || value.error, null, 2);
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
  document.querySelector("#status-button").addEventListener("click", async () => {
    try { await start({ kind: "status" }); } catch (error) { state.textContent = error.message; }
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
    try { await start(body); } catch (error) { state.textContent = error.message; }
  });
  document.querySelector("#cancel-button").addEventListener("click", async () => {
    if (!activeTask) return;
    try { await request(`/api/tasks/${activeTask}`, { method: "DELETE", headers: { "X-Mercury-CSRF": csrf } }); } catch (error) { state.textContent = error.message; }
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
