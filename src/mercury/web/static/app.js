"use strict";
let csrf = "";
let activeTask = null;
const state = document.querySelector("#task-state");
const output = document.querySelector("#task-output");
const historyOutput = document.querySelector("#history-output");
const statusOutput = document.querySelector("#status-output");
const taskContext = document.querySelector("#task-context");
const translations = {
  en: {
    "skip": "Skip to task workspace", "brand-eyebrow": "Internal network diagnostics", "scope": "Private-network scope active",
    "workspace-eyebrow": "Operator workspace", "workspace-title": "Find the path that still gets through.", "workspace-copy": "Run a bounded local check, internal mapping, or paired coverage assessment. Results retain the exact direction, profile, and evidence collected.",
    "status-eyebrow": "Read only", "status-title": "Local status", "status-copy": "Collect interfaces, routes, DNS, neighbour and native-capability evidence without sending probes.", "status-button": "Collect passive status", "status-empty": "Awaiting collection.",
    "semantics-eyebrow": "Interpretation", "semantics-title": "Evidence stays precise", "semantics-copy": "Positive, negative, inconclusive, unavailable and error outcomes remain distinct. A gateway, neighbour cache entry or first route hop is not an observed switch.",
    "task-eyebrow": "Active work", "task-title": "Create an assessment", "kind-label": "Task kind", "kind-diagnose": "Diagnose one endpoint", "kind-discover-passive": "Passive discovery", "kind-discover": "Authorized discovery", "kind-trace": "Trace an internal route", "kind-paired": "Paired diagnostic", "kind-mapping": "Internal mapping", "kind-coverage": "Two-endpoint coverage",
    "target-label": "Target, network, or peer address", "scope-label": "Authorized CIDR scope", "profile-label": "Profile", "ports-label": "Ports (comma-separated)", "confirmation-label": "Full discovery confirmation", "coverage-profiles-label": "Profiles (comma-separated)", "config-path-label": "Paired configuration path", "identity-label": "Paired peer identity", "ranges-label": "Private CIDRs (comma-separated)", "rate-label": "Attempt-start rate", "concurrency-label": "Concurrency", "duration-label": "Duration (seconds)", "local-network-label": "Local private CIDR (ARP/ND context)", "peer-network-label": "Peer private CIDR (ARP/ND context)", "authorized-label": "I am authorized to test this target", "start-task": "Start task",
    "mapping-note": "Mapping accepts only private ranges and fixed profiles. Native Nmap profiles never accept free-form arguments. Duration 0 means no added operator cutoff, within hard ceilings.", "coverage-note": "Coverage reports the tested profile, direction, packet shape and time window; it does not claim every possible tunnel has been excluded.", "task-ready": "Ready for a new task.", "cancel-task": "Cancel active task", "task-output": "Task output will appear here.",
    "coverage-result-eyebrow": "Assessment result", "coverage-result-title": "Coverage evidence and gaps", "coverage-result-note": "Rows describe only emitted profiles, ports, directions and the recorded time window.", "table-profile": "Profile", "table-direction": "Direction", "table-port": "Port", "table-outcome": "Outcome", "table-evidence": "Evidence", "table-provenance": "Provenance", "signal-eyebrow": "Signal", "candidate-title": "Candidate carriers", "boundary-eyebrow": "Coverage boundary", "gaps-title": "Coverage gaps",
    "history-eyebrow": "Local record", "history-title": "History and reports", "history-button": "Refresh completed history", "compare-left-label": "Earlier task ID", "compare-right-label": "Later task ID", "compare-button": "Compare tasks", "report-task-label": "Task ID for redacted HTML report", "report-button": "Open redacted report", "history-empty": "No history requested yet.",
    "context-empty": "Choose a task to show its inputs.", "context-diagnose": "Check one selected private endpoint.", "context-discover-passive": "Read local network facts without probes.", "context-discover": "Map one authorized private CIDR with a fixed profile.", "context-trace": "Collect bounded route evidence for one private target.", "context-paired": "Run the configured reciprocal peer diagnostic.", "context-mapping": "Map selected private ranges with bounded rate and duration.", "context-coverage": "Test configured receiver profiles in both directions.",
    "language-toggle": "Switch to Chinese", "task-state": "Task {state}", "coverage-gap": "coverage gap", "no-evidence": "no recorded evidence", "not-observed": "not observed", "gap-detail": "{profile} {direction}: no recorded evidence in this assessment.", "candidate-detail": "{profile} {direction}: positive evidence was recorded.", "no-candidates": "No positive candidate carrier was recorded in this finite assessment.", "no-gaps": "No profile-direction row was empty; inspect unavailable and inconclusive evidence above.",
  },
  zh: {
    "skip": "跳至任务工作区", "brand-eyebrow": "内网网络诊断", "scope": "私有网络范围已启用",
    "workspace-eyebrow": "操作工作区", "workspace-title": "找到仍然可以通过的路径。", "workspace-copy": "执行受限的本地检查、内网测绘或双端覆盖评估。结果会保留实际方向、配置文件与采集到的证据。",
    "status-eyebrow": "只读", "status-title": "本机状态", "status-copy": "不发送探测包，采集网卡、路由、DNS、邻居信息及本机能力证据。", "status-button": "采集被动状态", "status-empty": "等待采集。",
    "semantics-eyebrow": "结果解释", "semantics-title": "证据保持精确", "semantics-copy": "肯定、否定、不确定、不可用和错误结果彼此独立。网关、邻居缓存条目或首跳路由都不等同于已观测到的交换机。",
    "task-eyebrow": "主动任务", "task-title": "创建评估", "kind-label": "任务类型", "kind-diagnose": "诊断单个端点", "kind-discover-passive": "被动发现", "kind-discover": "授权发现", "kind-trace": "跟踪内网路由", "kind-paired": "双端诊断", "kind-mapping": "内网测绘", "kind-coverage": "双端覆盖评估",
    "target-label": "目标、网段或对端地址", "scope-label": "已授权 CIDR 范围", "profile-label": "配置文件", "ports-label": "端口（逗号分隔）", "confirmation-label": "全量发现确认码", "coverage-profiles-label": "配置文件（逗号分隔）", "config-path-label": "双端配置文件路径", "identity-label": "对端身份标识", "ranges-label": "私有 CIDR（逗号分隔）", "rate-label": "每秒尝试起始速率", "concurrency-label": "并发数", "duration-label": "时长（秒）", "local-network-label": "本机私有 CIDR（ARP/ND 语境）", "peer-network-label": "对端私有 CIDR（ARP/ND 语境）", "authorized-label": "我已获授权测试此目标", "start-task": "开始任务",
    "mapping-note": "测绘仅接受私有网段和固定配置文件。原生 Nmap 配置文件不接受自由参数。时长 0 表示不增加操作员提前截止时间，但仍受硬性上限约束。", "coverage-note": "覆盖评估会报告已测试的配置文件、方向、报文形状和时间窗口；它不会声称所有可能的隧道都已被排除。", "task-ready": "已就绪，可创建新任务。", "cancel-task": "取消当前任务", "task-output": "任务输出将显示在这里。",
    "coverage-result-eyebrow": "评估结果", "coverage-result-title": "覆盖证据与缺口", "coverage-result-note": "各行仅描述本次实际发出的配置文件、端口、方向及记录时间窗口。", "table-profile": "配置文件", "table-direction": "方向", "table-port": "端口", "table-outcome": "结果", "table-evidence": "证据", "table-provenance": "来源", "signal-eyebrow": "信号", "candidate-title": "候选承载通道", "boundary-eyebrow": "覆盖边界", "gaps-title": "覆盖缺口",
    "history-eyebrow": "本地记录", "history-title": "历史与报告", "history-button": "刷新已完成历史", "compare-left-label": "较早任务 ID", "compare-right-label": "较晚任务 ID", "compare-button": "比较任务", "report-task-label": "生成脱敏 HTML 报告的任务 ID", "report-button": "打开脱敏报告", "history-empty": "尚未请求历史记录。",
    "context-empty": "选择一种任务以显示所需输入。", "context-diagnose": "检查一个选定的私有端点。", "context-discover-passive": "不发送探测包，读取本地网络事实。", "context-discover": "用固定配置文件测绘一个已授权的私有 CIDR。", "context-trace": "为一个私有目标采集受限的路由证据。", "context-paired": "运行已配置的双向对端诊断。", "context-mapping": "在受限速率与时长内测绘选定的私有网段。", "context-coverage": "在两个方向测试已配置的接收端配置文件。",
    "language-toggle": "切换为英文", "task-state": "任务状态：{state}", "coverage-gap": "覆盖缺口", "no-evidence": "未记录证据", "not-observed": "未观测到", "gap-detail": "{profile} {direction}：本次评估未记录证据。", "candidate-detail": "{profile} {direction}：记录到了肯定证据。", "no-candidates": "本次有限评估未记录到肯定的候选承载通道。", "no-gaps": "没有配置文件-方向行为空；请检查上方不可用及不确定证据。",
  },
};
let language = "en";
function text(key, values = {}) {
  return (translations[language][key] || translations.en[key] || key).replace(/\{(\w+)\}/g, (_, name) => values[name] ?? "");
}
function applyLanguage(nextLanguage, { persist = true } = {}) {
  language = nextLanguage === "zh" ? "zh" : "en";
  document.documentElement.lang = language === "zh" ? "zh-CN" : "en";
  for (const element of document.querySelectorAll("[data-i18n]")) {
    if ((element.id === "task-state" && activeTask) || (element.matches("pre") && element.dataset.populated === "true")) continue;
    element.textContent = text(element.dataset.i18n);
  }
  const toggle = document.querySelector("#language-toggle");
  toggle.textContent = language === "zh" ? "EN" : "中文";
  toggle.setAttribute("aria-label", text("language-toggle"));
  if (persist) {
    try { localStorage.setItem("mercury-language", language); } catch (_) { /* Storage is optional. */ }
  }
  syncTaskForm();
}
const taskDescriptions = {
  diagnose: "context-diagnose", discover_passive: "context-discover-passive", discover: "context-discover",
  trace: "context-trace", paired: "context-paired", mapping: "context-mapping", coverage: "context-coverage",
};
function field(name) { return document.querySelector(name).value.trim(); }
function csv(name) { return field(name) ? field(name).split(",").map((value) => value.trim()).filter(Boolean) : []; }
function integer(name, fallback) { const value = Number(field(name)); return Number.isInteger(value) ? value : fallback; }
function syncTaskForm() {
  const kind = field("#kind");
  taskContext.textContent = text(taskDescriptions[kind] || "context-empty");
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
      const port = first?.detail?.receiver_destination_port ?? first?.detail?.port ?? "\u2014";
      const outcome = evidence.length ? evidence.map((item) => item.disposition).join(", ") : text("coverage-gap");
      cell(row, profile); cell(row, direction); cell(row, String(port)); cell(row, outcome);
      cell(row, evidence.map((item) => item.evidence_kind).join(", ") || text("no-evidence"));
      cell(row, evidence.map((item) => item.source).filter(Boolean).join(", ") || text("not-observed"));
      body.appendChild(row);
      if (!evidence.length) listItem(gaps, text("gap-detail", { profile, direction }));
      if (evidence.some((item) => item.disposition === "positive")) listItem(candidates, text("candidate-detail", { profile, direction }));
    }
  }
  if (!candidates.children.length) listItem(candidates, text("no-candidates"));
  if (!gaps.children.length) listItem(gaps, text("no-gaps"));
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
    state.textContent = text("task-state", { state: value.state });
    if (value.result || value.error) {
      const destination = currentTask.presentation === "status" ? statusOutput : output;
      destination.textContent = JSON.stringify(value.result || value.error, null, 2);
      destination.dataset.populated = "true";
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
  let preferredLanguage = navigator.language.toLowerCase().startsWith("zh") ? "zh" : "en";
  try { preferredLanguage = localStorage.getItem("mercury-language") || preferredLanguage; } catch (_) { /* Storage is optional. */ }
  applyLanguage(preferredLanguage, { persist: false });
  document.querySelector("#language-toggle").addEventListener("click", () => applyLanguage(language === "zh" ? "en" : "zh"));
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
