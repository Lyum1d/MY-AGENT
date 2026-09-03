/* SRC 渗透 Agent 控制台前端 */

let state = {
  projects: [],
  currentProject: null,
  sessionId: null,
  eventSource: null,
  tools: [],
  steps: [],
  confirmed: false,
  models: null, // { current, items: [...] }
};

/* ---------- 工具函数 ---------- */
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));

function log(text, cls = '') {
  const box = $('log');
  if (box.textContent.trim() === '等待任务…') box.textContent = '';
  const span = document.createElement('span');
  span.className = cls;
  span.textContent = text + '\n';
  box.appendChild(span);
  box.scrollTop = box.scrollHeight;
}

async function api(path, opts = {}) {
  const r = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
}

/* ---------- 初始化 ---------- */
async function init() {
  try {
    const h = await api('/api/health');
    const dot = h.llm.ready ? '<span class="dot ok"></span>' : '<span class="dot bad"></span>';
    const backendLabel = h.current_backend === 'ollama' ? '本地' : '云端';
    $('status').innerHTML = `
      ${dot}<b>模型</b> ${esc(h.models[h.current_backend] || '')}（${backendLabel}，${h.llm.ready ? '就绪' : '未就绪'}）
      · <b>本地工具</b> ${h.registry.launchable}
      · <b>可编排</b> ${h.registry.scriptable}
      · <b>网页</b> ${h.registry.web}
      · <b>缺失</b> ${h.registry.missing}`;
  } catch (e) {
    $('status').innerHTML = `<span class="dot bad"></span>后端未连接：${esc(e.message)}`;
  }
  loadProjects();
  loadTools();
  loadModels();
}

/* ---------- 模型切换 ---------- */
async function loadModels() {
  try {
    const d = await api('/api/models');
    state.models = d;
    renderModelSelect();
  } catch (e) { /* 后端未连接时静默，状态栏已报错 */ }
}

function renderModelSelect() {
  const sel = $('modelSelect');
  const d = state.models;
  if (!sel || !d) return;
  sel.innerHTML = d.items.map(m => `
    <option value="${esc(m.name)}" ${m.name === d.current ? 'selected' : ''} ${m.available ? '' : 'disabled'}>
      ${esc(m.label)} · ${esc(m.model)}${m.available ? '' : '（未配置）'}
    </option>`).join('');
}

async function switchModel(name) {
  if (!name || (state.models && name === state.models.current)) return;
  try {
    const d = await api('/api/models', {
      method: 'POST',
      body: JSON.stringify({ backend: name }),
    });
    if (state.models) state.models.current = d.current;
    renderModelSelect();
    log(`[模型] 决策后端已切换：${d.current}（${d.model}），下一个任务生效`, 'c-ok');
  } catch (e) {
    log(`[模型] 切换失败：${e.message}`, 'c-err');
    loadModels(); // 恢复下拉框显示，与服务端实际状态保持一致
  }
}

/* ---------- 项目 ---------- */
async function loadProjects() {
  const d = await api('/api/projects');
  state.projects = d.items;
  const el = $('projectList');
  if (!d.items.length) {
    el.innerHTML = '<div class="empty">还没有项目，先建一个</div>';
    return;
  }
  el.innerHTML = d.items.map(p => `
    <div class="list-item ${state.currentProject === p.id ? 'active' : ''}"
         onclick="selectProject('${p.id}')">
      <div class="name">${esc(p.name)}</div>
      <div class="meta">${esc(p.target || '无目标')} · 漏洞 ${p.finding_count}</div>
    </div>`).join('');
}

async function createProject() {
  const name = $('pName').value.trim();
  if (!name) return alert('请填写项目名称');
  const p = await api('/api/projects', {
    method: 'POST',
    body: JSON.stringify({ name, target: $('pTarget').value.trim() }),
  });
  $('pName').value = ''; $('pTarget').value = '';
  state.currentProject = p.id;
  loadProjects();
  loadFindings();
}

async function selectProject(pid) {
  state.currentProject = pid;
  loadProjects();
  loadFindings();
}

/* ---------- 工具箱 ---------- */
async function loadTools() {
  const d = await api('/api/tools?kind=all');
  state.tools = d.items;
  renderTools();
}

function renderTools() {
  const kw = $('toolSearch').value.trim().toLowerCase();
  const kind = $('toolKind').value;
  let items = state.tools.filter(t => {
    if (kind === 'web') return !!t.url;
    if (kind === 'launchable') return !!t.exists && !t.url;
    if (kind === 'scriptable') return !!t.scriptable;
    return true;
  });
  if (kw) items = items.filter(t =>
    t.name.toLowerCase().includes(kw) || t.alias.toLowerCase().includes(kw));

  const groups = {};
  items.forEach(t => (groups[t.category] = groups[t.category] || []).push(t));

  $('toolList').innerHTML = Object.entries(groups).map(([cat, list]) => `
    <div class="tool-group">${esc(cat)} (${list.length})</div>
    ${list.map(t => {
      const badge = t.url
        ? '<span class="badge">网页</span>'
        : t.disabled
          ? '<span class="badge off">已禁用</span>'
          : t.scriptable
            ? `<span class="badge ${t.risk_level}">${t.risk_level}</span>`
            : '<span class="badge gui">GUI</span>';
      const click = t.url ? `window.open('${t.url}')` : `launchTool('${t.alias}')`;
      return `<div class="tool" onclick="${click}" title="${esc(t.path || t.url)}">
                <span class="tname">${esc(t.name)}</span>${badge}
              </div>`;
    }).join('')}
  `).join('') || '<div class="empty">无匹配工具</div>';
}

async function launchTool(alias) {
  try {
    const r = await api(`/api/tools/launch/${alias}`, { method: 'POST' });
    log(r.ok ? `[启动] ${r.message}` : `[启动失败] ${r.message}`, r.ok ? 'c-ok' : 'c-err');
  } catch (e) {
    log(`[启动失败] ${e.message}`, 'c-err');
  }
}

/* ---------- 任务执行 ---------- */
async function sendTask() {
  const msg = $('taskInput').value.trim();
  if (!msg) return;
  $('taskInput').value = '';
  $('sendBtn').disabled = true;
  $('confirmBox').innerHTML = '';
  state.steps = [];
  renderSteps();

  if (!state.currentProject) {
    log('[提示] 未选择项目，任务结果不会归档到项目下', 'c-mute');
  }

  const s = await api('/api/sessions', { method: 'POST' });
  state.sessionId = s.session_id;

  await api(`/api/sessions/${s.session_id}/run`, {
    method: 'POST',
    body: JSON.stringify({ message: msg, project_id: state.currentProject || '' }),
  });

  connectStream(s.session_id);
}

function connectStream(sid) {
  if (state.eventSource) state.eventSource.close();
  const es = new EventSource(`/api/sessions/${sid}/stream`);
  state.eventSource = es;

  es.onmessage = (e) => {
    const ev = JSON.parse(e.data);
    handleEvent(ev);
  };
  es.onerror = () => {
    es.close();
    $('sendBtn').disabled = false;
  };
}

function handleEvent(ev) {
  switch (ev.type) {
    case 'session_start':
      $('log').textContent = '';
      log(`▶ 会话 ${ev.session_id} 已开始`, 'c-mute');
      break;
    case 'model':
      log(`◉ 本轮决策模型：${ev.data.label}（${ev.data.model}）`, 'c-ok');
      break;
    case 'target':
      log(`◎ 识别到目标：${ev.data}`, 'c-ok');
      break;
    case 'thinking':
      log(`… ${ev.data}`, 'c-mute');
      break;
    case 'reasoning':
      log(`◆ ${ev.data}`, 'c-model');
      break;
    case 'command':
      log(`$ ${ev.data}`, 'c-cmd');
      break;
    case 'output':
      log('  ' + ev.data);
      break;
    case 'exit':
      log(`— 退出码 ${ev.code}`, ev.code === 0 ? 'c-mute' : 'c-err');
      break;
    case 'step_start':
      upsertStep(ev.step);
      break;
    case 'step_done':
      upsertStep(ev.step);
      break;
    case 'step_denied':
      upsertStep(ev.step);
      break;
    case 'error':
      log(`✗ ${ev.data}`, 'c-err');
      break;
    case 'need_confirm':
      showConfirm(ev);
      break;
    case 'answer':
      log(`\n✔ 结论：\n${ev.data}`, 'c-ok');
      break;
    case 'done':
      log(`\n■ 结束（${ev.state}），共 ${state.steps.length} 步`, 'c-mute');
      $('sendBtn').disabled = false;
      state.eventSource.close();
      if (state.currentProject) loadFindings();
      break;
  }
}

/* ---------- 执行计划 ---------- */
function upsertStep(step) {
  const i = state.steps.findIndex(s => s.id === step.id);
  if (i >= 0) state.steps[i] = step; else state.steps.push(step);
  renderSteps();
}

function renderSteps() {
  const el = $('stepList');
  $('stepCount').textContent = `${state.steps.length} 步`;
  if (!state.steps.length) {
    el.innerHTML = '<div class="empty">尚未执行任务</div>';
    return;
  }
  el.innerHTML = state.steps.map((s, i) => `
    <div class="step">
      <span class="idx">${i + 1}</span>
      <span class="badge ${s.risk.level}">${s.risk.level}</span>
      <span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
        ${esc(s.tool_name)} → ${esc(s.target || '(无参数)')}
      </span>
      <span class="st ${s.status}">${s.status}</span>
    </div>`).join('');
}

/* ---------- 高危确认 ---------- */
function showConfirm(ev) {
  const s = ev.step;
  const needDouble = ev.risk.double_confirm;
  $('confirmBox').innerHTML = `
    <div class="confirm">
      <div class="title">⚠ 需要授权：${esc(s.tool_name)}（风险等级 ${ev.risk.level}）</div>
      <div class="desc">
        目标：<code>${esc(s.target || '(无)')}</code>　参数：<code>${esc(s.args || '(无)')}</code><br>
        判定依据：${esc(ev.risk.reason || ev.risk.name)}
      </div>
      <div class="actions">
        ${needDouble ? '<label><input type="checkbox" id="authChk"> 我确认已获得该目标的书面授权</label>' : ''}
        <button class="primary" onclick="doConfirm(true)">放行</button>
        <button class="danger" onclick="doConfirm(false)">拒绝</button>
      </div>
    </div>`;
}

async function doConfirm(approved) {
  const chk = $('authChk');
  if (approved && chk && !chk.checked) {
    return alert('请先勾选授权确认');
  }
  $('confirmBox').innerHTML = '';
  log(approved ? '→ 已放行' : '→ 已拒绝', approved ? 'c-ok' : 'c-err');
  await api(`/api/sessions/${state.sessionId}/confirm`, {
    method: 'POST',
    body: JSON.stringify({ approved }),
  });
}

/* ---------- 漏洞发现 ---------- */
function toggleFindingForm() {
  const el = $('findingForm');
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

async function loadFindings() {
  if (!state.currentProject) return;
  const d = await api(`/api/projects/${state.currentProject}`);
  const el = $('findingList');
  if (!d.findings.length) {
    el.innerHTML = '<div class="empty">暂无记录</div>';
    return;
  }
  el.innerHTML = d.findings.map(f => `
    <div class="finding">
      <div class="ftitle">${esc(f.title)} <span class="badge">${esc(f.severity)}</span></div>
      <div class="fmeta">${esc(f.target || '无目标')}</div>
      <div style="margin-top:6px;">
        <button class="sm danger" onclick="delFinding('${f.id}')">删除</button>
      </div>
    </div>`).join('');
}

async function addFinding() {
  if (!state.currentProject) return alert('请先选择项目');
  const title = $('fTitle').value.trim();
  if (!title) return alert('请填写漏洞名称');
  await api(`/api/projects/${state.currentProject}/findings`, {
    method: 'POST',
    body: JSON.stringify({
      title,
      severity: $('fSev').value,
      target: $('fTarget').value.trim(),
      detail: $('fDetail').value.trim(),
      evidence: $('fEvidence').value.trim(),
    }),
  });
  ['fTitle', 'fTarget', 'fDetail', 'fEvidence'].forEach(id => $(id).value = '');
  toggleFindingForm();
  loadFindings();
  loadProjects();
}

async function delFinding(fid) {
  await api(`/api/projects/${state.currentProject}/findings/${fid}`, { method: 'DELETE' });
  loadFindings();
  loadProjects();
}

/* ---------- 报告 ---------- */
async function viewReport() {
  if (!state.currentProject) return alert('请先选择项目');
  const d = await api(`/api/projects/${state.currentProject}/report`);
  window.open('data:text/markdown;charset=utf-8,' + encodeURIComponent(d.markdown), '_blank');
}

async function exportReport() {
  if (!state.currentProject) return alert('请先选择项目');
  const d = await api(`/api/projects/${state.currentProject}/report/export`, { method: 'POST' });
  log(`[导出] 报告已保存至 ${d.path}`, 'c-ok');
}

/* ---------- 标签切换 ---------- */
document.querySelectorAll('.tab').forEach(t => {
  t.onclick = () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    $('tab-proj').style.display = t.dataset.tab === 'proj' ? 'flex' : 'none';
    $('tab-tools').style.display = t.dataset.tab === 'tools' ? 'flex' : 'none';
  };
});

init();
