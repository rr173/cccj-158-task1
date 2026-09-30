/* MedIdx 前端：全部界面与 API 交互。原始身份仅在回链领取响应中出现。 */
const App = (() => {
  const $ = (id) => document.getElementById(id);
  let token = null, me = null, state = { projects: [], imagesByProject: {}, policies: {} };

  async function api(method, path, body) {
    const opts = { method, headers: { Authorization: token ? `Bearer ${token}` : {} } };
    if (body instanceof FormData) opts.body = body;
    else if (body) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    const res = await fetch(path, opts);
    const ct = res.headers.get("content-type") || "";
    const data = ct.includes("json") ? await res.json() : await res.text();
    if (!res.ok) {
      const msg = data && data.error ? `${data.error.code}: ${data.error.message}` : `HTTP ${res.status}`;
      throw new Error(msg);
    }
    return data;
  }
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const fmt = (s) => esc((s || "").replace("T", " ").replace("Z", " UTC"));
  const statusPill = (s) => `<span class="status s-${esc(s)}">${esc(s)}</span>`;

  // ---------- 登录 ----------
  async function login(username) {
    const r = await api("POST", "/api/login", { username });
    token = r.token; me = r.user; localStorage.setItem("medidx_token", token);
    $("login").classList.add("hidden");
    $("app").classList.remove("hidden");
    renderUser();
    await refreshAll();
  }
  function renderUser() {
    $("userbox").innerHTML =
      `<span class="pill ${me.role}">${esc(me.display_name)} · ${esc(me.role)}</span>` +
      `<button class="link" onclick="App.logout()">退出</button>`;
  }
  function logout() { localStorage.removeItem("medidx_token"); location.reload(); }

  // ---------- 项目 ----------
  async function createProject() {
    const name = $("pname").value.trim();
    if (!name) return alert("请输入项目名");
    await api("POST", "/api/projects", { name, description: $("pdesc").value });
    $("pname").value = $("pdesc").value = "";
    await refreshAll();
  }
  async function refreshProjects() {
    const { projects } = await api("GET", "/api/projects");
    state.projects = projects;
    const opts = projects.map(p => `<option value="${p.id}">${esc(p.name)}</option>`).join("");
    $("ingestProject").innerHTML = opts;
    $("policyProject").innerHTML = opts;
    $("grantImage").innerHTML = "";
    let html = "";
    for (const p of projects) {
      const { images } = await api("GET", `/api/projects/${p.id}/images`);
      state.imagesByProject[p.id] = images;
      html += `<div class="rulebox"><b>${esc(p.name)}</b> <small class="hint">${esc(p.description)}</small>`
        + images.map(renderImage).join("") + `</div>`;
      for (const im of images) {
        const label = `${p.name} · ${im.id.slice(0, 8)} · v${im.current_revision}`;
        $("grantImage").innerHTML += `<option value="${im.id}">${esc(label)}</option>`;
      }
    }
    $("projects").innerHTML = html || `<p class="hint">暂无项目。也可用 CLI 播种：python -m medidx.cli init-demo</p>`;
  }

  function renderImage(im) {
    const vnodes = im.versions.map(v =>
      `<span class="vnode">v${v.revision} ${statusPill(v.status)}<br>
        <small class="hint">${esc(v.reason)}</small></span>`).join(" → ");
    const canInspect = im.versions.some(v => v.status === "pending_qc" || v.status === "published");
    return `<div style="margin:8px 0">
      <code>${esc(im.id.slice(0, 12))}</code> <small class="hint">${esc(im.media_type)} · ${fmt(im.created_at)}</small>
      <button class="link" onclick="App.showImage('${im.id}')">查看版本链/发起修订</button>
      <div class="vchain">${vnodes}</div><div id="img-${esc(im.id)}"></div></div>`;
  }

  async function showImage(imageId) {
    const { versions } = await api("GET", `/api/images/${imageId}/versions`);
    const el = $(`img-${imageId}`);
    if (el.dataset.open) { el.innerHTML = ""; el.dataset.open = ""; return; }
    el.dataset.open = "1";
    const rows = versions.map(v => {
      const updatable = v.status === "published" || v.status === "rejected";
      return `<tr><td>v${v.revision}</td><td>${statusPill(v.status)}</td>
        <td>${esc(v.policy_name)} v${v.policy_version}</td><td>${esc(v.reason)}</td>
        <td>${v.findings.length} 条质检 / ${v.attempts.length} 次尝试</td>
        <td><button class="link" onclick="App.showVersion('${v.id}')">详情</button>
        ${updater(updatable, imageId)}</td></tr>`;
    }).join("");
    function updater(ok, iid) {
      if (!ok) return "";
      return `<button class="link" onclick="App.newRevision('${iid}','policy_upgrade')">策略升级重处理</button>
              <button class="link" onclick="App.newRevision('${iid}','clinical_correction')">临床纠错重处理</button>`;
    }
    el.innerHTML = `<table><tr><th>版本</th><th>状态</th><th>策略</th><th>原因</th><th>质检</th><th>操作</th></tr>${rows}</table>
      <p class="hint">策略升级/纠错永远产生新 revision；旧版本（含已驳回版）冻结保留。
      同一影像同时只允许一个待质检版本。</p>`;
  }

  async function showVersion(vid) {
    const v = await api("GET", `/api/versions/${vid}`);
    openQcTab();
    $("qcDetail").classList.remove("hidden");
    const findings = v.findings.map(f =>
      `<li class="${f.severity}">[${esc(f.severity)}] <b>${esc(f.code)}</b>：${esc(f.message)}</li>`).join("");
    const steps = v.steps.map(s => {
      let detail = "";
      try { detail = JSON.stringify(JSON.parse(s.detail_json), null, 1); } catch { detail = s.detail_json; }
      return `${String(s.step_no).padStart(2, "0")}  ${s.name.padEnd(22)} ${detail}`;
    }).join("\n");
    const attempts = v.attempts.map(a =>
      `#${a.attempt_no} ${a.result} ${a.error_code ? "(" + esc(a.error_code) + ")" : ""} @${esc(a.worker_id)}`)
      .join("\n");
    const elements = v.elements ? renderElements(v.elements) : `<p class="hint">无工件（处理未完成或被驳回）</p>`;
    $("qcDetailBody").innerHTML = `
      <p>影像 <code>${esc(v.image_id.slice(0, 12))}</code> · 版本 <b>v${v.revision}</b>
        ${statusPill(v.status)} · 策略 ${esc(v.policy_name)} v${v.policy_version}
        · 原因 ${esc(v.reason)}</p>
      <div class="grid2">
        <div><h4>派生像素（红=识别到的 PHI 文本位置，黑块=遮盖）</h4>${v.svg || ""}</div>
        <div><h4>去标识后标签</h4>${elements}</div>
      </div>
      <h4>质检发现</h4><ul>${findings || '<li class="info">无</li>'}</ul>
      <div class="grid2">
        <div><h4>处理尝试（只增）</h4><div class="steps">${esc(attempts) || "无"}</div></div>
        <div><h4>处理步骤（只增）</h4><div class="steps">${esc(steps)}</div></div>
      </div>
      <p>
        <button ${v.status !== "pending_qc" ? "disabled" : ""} onclick="App.publish('${v.id}')">✅ 质检通过并发布</button>
        <button ${v.status !== "pending_qc" ? "disabled" : ""} onclick="App.reject('${v.id}')">⛔ 驳回</button>
        <small class="hint">发布时会重新读取工件做二次残留 PHI 复验；任何 blocker 都无法发布。</small>
      </p>`;
  }
  function renderElements(elements) {
    const rows = Object.entries(elements).map(([tag, val]) =>
      `<tr><td><code>${esc(tag)}</code></td><td>${esc(Array.isArray(val) ? val.join("\\") : val)}</td></tr>`).join("");
    return `<table>${rows}</table>`;
  }
  function openQcTab() { switchTab("qc"); }

  async function newRevision(imageId, reason) {
    let policyId = null;
    if (reason === "policy_upgrade") {
      const p = state.projects.find(x =>
        (state.imagesByProject[x.id] || []).some(i => i.id === imageId));
      const pols = await api("GET", `/api/projects/${p.id}/policies`);
      const cur = prompt(`输入要应用的策略 ID（留空=项目最新）。可用：\n` +
        pols.map(x => `${x.name} v${x.version} -> ${x.id}`).join("\n"));
      policyId = cur || null;
    }
    await api("POST", `/api/images/${imageId}/revisions`, { reason, policy_id: policyId });
    alert("新派生版本已入队。到「处理队列」运行 worker，再到「质检发布」验收。");
  }

  // ---------- 入库 ----------
  async function ingest() {
    const pid = $("ingestProject").value;
    const f = $("dicomFile").files[0];
    if (!f) return alert("请选择文件");
    const fd = new FormData();
    fd.append("project_id", pid);
    fd.append("file", f, f.name);
    fd.append("media_type", f.name.endsWith(".dcm") ? "dcm" : "json");
    const r = await api("POST", "/api/ingest", fd);
    alert(r.already_exists ? "该内容已入库（幂等）" : "已冻结并入队，版本 v1 待处理");
    await refreshProjects();
  }

  // ---------- 队列 ----------
  async function pump(n) {
    await api("POST", "/api/worker/pump", { max_jobs: n });
    await refreshQueue();
  }
  async function refreshQueue() {
    const { jobs } = await api("GET", "/api/queue");
    $("queue").innerHTML = jobs.length ? `<table><tr><th>影像</th><th>状态</th><th>尝试</th>
      <th>租约</th><th>错误</th><th>操作</th></tr>` +
      jobs.map(j => `<tr><td><code>${esc(j.image_id.slice(0, 10))}</code></td>
        <td>${statusPill(j.status)}</td><td>${j.attempts}</td>
        <td>${esc(j.lease_owner || "-")}</td><td class="blocker">${esc(j.last_error || "")}</td>
        <td>${["dead", "queued"].includes(j.status)
          ? `<button class="link" onclick="App.retry('${j.image_id}')">人工批量重试</button>` : ""}</td></tr>`).join("")
      + "</table>" : `<p class="hint">队列为空</p>`;
  }
  async function retry(imageId) {
    await api("POST", `/api/images/${imageId}/retry`, {});
    await refreshQueue();
  }

  // ---------- 质检 ----------
  async function refreshQc() {
    const { queue } = await api("GET", "/api/qc/pending");
    $("qcPending").innerHTML = queue.length ? `<table><tr><th>影像</th><th>版本</th>
      <th>策略</th><th>遮盖区</th><th>创建</th><th></th></tr>` +
      queue.map(v => `<tr><td><code>${esc(v.image_id.slice(0, 10))}</code></td>
        <td>v${v.revision}</td><td>${esc(v.policy_name)} v${v.policy_version}</td>
        <td>${v.mask_region_count}</td><td>${fmt(v.created_at)}</td>
        <td><button onclick="App.showVersion('${v.id}')">打开质检</button></td></tr>`).join("")
      + "</table>" : `<p class="hint">没有待质检版本（先运行 Worker）</p>`;
  }

  async function publish(vid) {
    await api("POST", `/api/versions/${vid}/publish`, {});
    await refreshAll();
    await showVersion(vid);
  }
  async function reject(vid) {
    const reason = prompt("驳回原因（将记入质检发现）", "人工复核不通过");
    if (reason === null) return;
    await api("POST", `/api/versions/${vid}/reject`, { reason });
    await refreshAll();
  }

  // ---------- 策略 ----------
  async function refreshPolicies() {
    const pid = $("policyProject").value;
    if (!pid) return;
    const { policies } = await api("GET", `/api/projects/${pid}/policies`);
    state.policies[pid] = policies;
    $("policyList").innerHTML = policies.map(p =>
      `<div class="vnode"><b>${esc(p.name)}</b> v${p.version} · ${p.rules_count} 条规则
       <small class="hint">${fmt(p.created_at)} ${esc(p.notes)}</small></div>`).join("")
      || `<p class="hint">无策略</p>`;
  }
  async function createPolicy() {
    const body = { project_id: $("policyProject").value, name: $("policyName").value.trim(),
      base_version: Number($("baseVersion").value), rules: null, notes: $("policyNotes").value };
    const p = await api("POST", "/api/policies", body);
    alert(`已创建策略 ${p.name} v${p.version}（旧版本保留）。对影像发起"策略升级重处理"即可生成新派生版本。`);
    await refreshPolicies();
  }

  // ---------- 回链 ----------
  async function createGrant() {
    const body = { image_id: $("grantImage").value, purpose: $("grantPurpose").value.trim(),
      window_start: $("winStart").value, window_end: $("winEnd").value,
      approver_username: $("grantApprover").value };
    try {
      const r = await api("POST", "/api/relink/grants", body);
      $("grantResult").innerHTML =
        `<p class="ok">授权已创建（临床医生申请 + 隐私官审批）。请立即复制一次性令牌：</p>
         <div class="tokenbox">${esc(r.one_time_token)}</div>
         <button onclick="navigator.clipboard.writeText('${r.one_time_token}')">复制令牌</button>
         <p class="hint">授权绑定该病例/目的/时间窗；令牌只显示这一次，库内仅存其 SHA-256。</p>`;
    } catch (e) { alert(e.message); }
  }
  async function redeem() {
    try {
      const r = await api("POST", "/api/relink/redeem", { token: $("redeemToken").value.trim() });
      $("redeemResult").textContent = JSON.stringify(r, null, 2);
      $("redeemToken").value = "";
      await refreshGrants();
    } catch (e) { $("redeemResult").textContent = "拒绝回链：" + e.message; }
  }
  async function refreshGrants() {
    try {
      const { grants } = await api("GET", "/api/grants");
      $("grants").innerHTML = grants.length ? `<table><tr><th>病例</th><th>目的</th>
        <th>申请人</th><th>审批人</th><th>时间窗</th><th>状态</th><th></th></tr>` +
        grants.map(g => `<tr><td><code>${esc(g.image_id.slice(0, 10))}</code></td>
          <td>${esc(g.purpose)}</td><td>${esc(g.requester_name)}</td><td>${esc(g.approver_name)}</td>
          <td><small>${fmt(g.window_start)}<br>${fmt(g.window_end)}</small></td>
          <td>${statusPill(g.status)}<br><small class="hint">${esc(g.revoke_reason || "")}</small></td>
          <td>${g.status === "active"
            ? `<button class="danger-btn" onclick="App.revoke('${g.id}')">撤销</button>` : ""}</td></tr>`).join("")
        + "</table>" : `<p class="hint">暂无授权（仅隐私官/管理员可见）</p>`;
    } catch (e) { $("grants").innerHTML = `<p class="hint">${esc(e.message)}</p>`; }
  }
  async function revoke(gid) {
    const reason = prompt("撤销原因", "紧急撤销") || "";
    await api("POST", `/api/relink/grants/${gid}/revoke`, { reason });
    await refreshGrants();
  }

  // ---------- 审计 ----------
  async function refreshAudit() {
    const { events } = await api("GET", "/api/audit?limit=300");
    $("auditEvents").innerHTML = events.length ? `<table><tr><th>#</th><th>时间</th><th>动作</th>
      <th>对象</th><th>操作者</th><th>详情</th><th>链哈希(尾)</th></tr>` +
      events.map((e, i) => `<tr><td>${events.length - i}</td><td>${fmt(e.recorded_at)}</td>
        <td><code>${esc(e.action)}</code></td><td>${esc(e.object_type)} ${esc((e.object_id || "").slice(0, 8))}</td>
        <td>${esc(e.actor_id || "").slice(2)}</td><td><small>${esc(e.detail_json)}</small></td>
        <td><code>${esc(e.entry_hash.slice(0, 10))}</code></td></tr>`).join("") + "</table>"
      : `<p class="hint">无事件</p>`;
  }
  async function verifyAudit() {
    try {
      const r = await api("GET", "/api/audit/verify");
      $("auditStatus").innerHTML = `<p class="ok">✅ 哈希链完整：${r.events} 条事件，链尖 ${r.tip.slice(0, 16)}…</p>`;
    } catch (e) { $("auditStatus").innerHTML = `<p class="bad">❌ ${esc(e.message)}</p>`; }
  }
  function exportAudit() {
    if (!token) return;
    // 带 Bearer 的下载：用 fetch 取文本再落盘
    fetch("/api/audit/export", { headers: { Authorization: `Bearer ${token}` } })
      .then(r => r.text()).then(csv => {
        const blob = new Blob(["﻿" + csv], { type: "text/csv" });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `medidx-audit-${Date.now()}.csv`; a.click();
      });
  }

  // ---------- 框架 ----------
  function switchTab(name) {
    document.querySelectorAll(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
    document.querySelectorAll(".tabpane").forEach(p => p.classList.add("hidden"));
    $(`tab-${name}`).classList.remove("hidden");
    if (name === "queue") refreshQueue();
    if (name === "qc") refreshQc();
    if (name === "policies") refreshPolicies();
    if (name === "relink") refreshGrants();
    if (name === "audit") refreshAudit();
  }

  async function refreshAll() {
    await refreshProjects();
    if ($("tab-queue") && !$("tab-queue").classList.contains("hidden")) await refreshQueue();
    await refreshQc();
  }

  // 初始化默认时间窗（当前起 1 小时）
  function initWindows() {
    const pad = (n) => String(n).padStart(2, "0");
    const d = new Date();
    const iso = (offMin) => {
      const x = new Date(d.getTime() + offMin * 60000);
      return `${x.getFullYear()}-${pad(x.getMonth() + 1)}-${pad(x.getDate())}T${pad(x.getHours())}:${pad(x.getMinutes())}`;
    };
    $("winStart").value = iso(-5); $("winEnd").value = iso(60);
  }

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll(".role").forEach(b => b.onclick = () => login(b.dataset.user));
    document.querySelectorAll(".tab").forEach(t => t.onclick = () => switchTab(t.dataset.tab));
    $("policyProject") && $("policyProject").addEventListener("change", refreshPolicies);
    initWindows();
    const saved = localStorage.getItem("medidx_token");
    if (saved) {
      token = saved;
      api("GET", "/api/me").then(r => { me = r.user;
        $("login").classList.add("hidden"); $("app").classList.remove("hidden");
        renderUser(); refreshAll();
      }).catch(() => logout());
    } else $("login").classList.remove("hidden");
  });

  return {
    login, logout, createProject, ingest, showImage, showVersion, newRevision,
    pump, retry, publish, reject, createPolicy, createGrant, redeem, revoke,
    verifyAudit, exportAudit, closeQc: () => $("qcDetail").classList.add("hidden"),
  };
})();
