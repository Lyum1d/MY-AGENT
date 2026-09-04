/* SRC 渗透 Agent 控制台前端 — 对话式界面 */

let state = {
  projects: [],
  currentProject: null,
  sessionId: null,
  eventSource: null,
  tools: [],
  steps: [],
  models: null,
  assistant: null,   // 当前 AI 气泡的 DOM 引用（streaming 时填充）
};

/* ---------- 工具函数 ---------- */
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s).replace(/[&<>"']/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

async function api(path, opts = {}) {
  const r = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...opts,
  });
  if (!r.ok) throw new Error((await r.json()).detail || r.statusText);
  return r.json();
}

function scrollToBottom() {
  const m = $('messages');
  m.scrollTop = m.scrollHeight;
}

function clearWelcome() {
  const w = $('welcome');
  if (w) w.remove();
}

/* 系统提示（非任务的日志，如「模型已切换」「项目已删除」） */
function log(text, cls = '') {
  clearWelcome();
  const box = $('messages');
  const line = document.createElement('div');
  line.className = 'sys-note ' + cls;
  line.textContent = text;
  box.appendChild(line);
  scrollToBottom();
}

/* 最小 markdown 渲染：代码块 / 行内代码 / 加粗 / 标题 / 列表 */
function md(text) {
  if (!text) return '';
  let s = esc(text);
  s = s.replace(/```[a-zA-Z]*\r?\n?([\s\S]*?)```/g, (_, code) =>
    `<pre class="code-block">${code.replace(/^\r?\n/, '').replace(/\r?\n$/, '')}</pre>`);
  s = s.replace(/`([^`\n]+)`/g, '<code>$1</code>');
  s = s.replace(/\*\*([^*\n]+)\*\*/g, '<b>$1</b>');
  s = s.replace(/^#{1,4}\s+(.+)$/gm, '<div class="md-h">$1</div>');
  s = s.replace(/^\s*[-*]\s+(.+)$/gm, '<div class="md-li">• $1</div>');
  s = s.replace(/\n/g, '<br>');
  return s;
}

/* ---------- 亮/暗主题 ---------- */
function applyTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  const btn = $('themeToggle');
  if (btn) btn.textContent = theme === 'light' ? '☀️' : '🌙';
  try { localStorage.setItem('src_theme', theme); } catch (e) {}
}

function toggleTheme() {
  const cur = document.documentElement.getAttribute('data-theme') || 'dark';
  applyTheme(cur === 'dark' ? 'light' : 'dark');
}

/* ---------- 消息气泡 ---------- */
function addUserMessage(text) {
  clearWelcome();
  const m = $('messages');
  const wrap = document.createElement('div');
  wrap.className = 'msg user';
  wrap.innerHTML = `<div class="avatar">🧑</div><div class="bubble">${esc(text)}</div>`;
  m.appendChild(wrap);
  scrollToBottom();
}

function createAssistant() {
  clearWelcome();
  const m = $('messages');
  const wrap = document.createElement('div');
  wrap.className = 'msg assistant';
  wrap.innerHTML = `
    <div class="avatar">🛡</div>
    <div class="bubble">
      <div class="bubble-meta">
        <span class="who">SRC Agent</span>
        <span class="meta-tags"></span>
      </div>
      <div class="bubble-steps"></div>
      <div class="bubble-body"></div>
      <div class="bubble-status"></div>
    </div>`;
  m.appendChild(wrap);
  state.assistant = {
    root: wrap,
    metaTags: wrap.querySelector('.meta-tags'),
    stepsEl: wrap.querySelector('.bubble-steps'),
    bodyEl: wrap.querySelector('.bubble-body'),
    statusEl: wrap.querySelector('.bubble-status'),
    outputEl: null,
  };
  scrollToBottom();
  return state.assistant;
}

function setAssistantMeta(tagText) {
  const a = state.assistant; if (!a) return;
  const tag = document.createElement('span');
  tag.className = 'tag';
  tag.textContent = tagText;
  a.metaTags.appendChild(tag);
}

function addTargetTag(target) {
  const a = state.assistant; if (!a) return;
  const tag = document.createElement('span');
  tag.className = 'tag target';
  tag.textContent = '目标：' + target;
  a.metaTags.appendChild(tag);
}

function setAssistantStatus(text) {
  const a = state.assistant; if (!a) return;
  a.statusEl.textContent = text;
  scrollToBottom();
}

function closeOutput() { if (state.assistant) state.assistant.outputEl = null; }

function appendReasoning(html) {
  const a = state.assistant; if (!a) return;
  closeOutput();
  const div = document.createElement('div');
  div.className = 'reasoning';
  div.innerHTML = html;
  a.bodyEl.appendChild(div);
  scrollToBottom();
}

function appendCommand(cmd) {
  const a = state.assistant; if (!a) return;
  closeOutput();
  const pre = document.createElement('pre');
  pre.className = 'code-block cmd';
  pre.textContent = '$ ' + cmd;
  a.bodyEl.appendChild(pre);
  scrollToBottom();
}

function appendOutput(text) {
  const a = state.assistant; if (!a) return;
  if (!a.outputEl) {
    const pre = document.createElement('pre');
    pre.className = 'code-block output';
    a.bodyEl.appendChild(pre);
    a.outputEl = pre;
  }
  a.outputEl.textContent += text + '\n';
  scrollToBottom();
}

function appendLine(text, cls = '') {
  const a = state.assistant; if (!a) return;
  closeOutput();
  const div = document.createElement('div');
  div.className = 'line ' + cls;
  div.textContent = text;
  a.bodyEl.appendChild(div);
  scrollToBottom();
}

function appendAnswer(mdHtml) {
  const a = state.assistant; if (!a) return;
  closeOutput();
  const div = document.createElement('div');
  div.className = 'answer-block';
  div.innerHTML = `<div class="answer-title">✔ 结论</div><div class="answer-body">${mdHtml}</div>`;
  a.bodyEl.appendChild(div);
  scrollToBottom();
}

function finalizeAssistant(stateName, stepCount) {
  const a = state.assistant; if (!a) return;
  a.statusEl.textContent = '';
  appendLine(`■ 结束（${stateName}），共 ${stepCount} 步`, 'muted');
  state.assistant = null;
}

/* ---------- 初始化 ---------- */
async function init() {
  // 同步主题按钮图标（主题本身已在 <head> 内联脚本里按 localStorage 设置，避免闪烁）
  const t = document.documentElement.getAttribute('data-theme') || 'dark';
  $('themeToggle').textContent = t === 'light' ? '☀️' : '🌙';

  await loadModels();
  try {
    const h = await api('/api/health');
    const dot = h.llm.ready ? '<span class="dot ok"></span>' : '<span class="dot bad"></span>';
    const cur = (state.models && state.models.items.find(m => m.name === h.current_backend)) || {};
    const label = cur.label || h.current_backend;
    $('status').innerHTML = `
      ${dot}<b>${esc(label)}</b> ${esc(h.current_model || cur.model || '')}（${h.llm.ready ? '就绪' : '未就绪'}）
      · <b>可编排</b> ${h.registry.scriptable}
      · <b>本地</b> ${h.registry.launchable}`;
  } catch (e) {
    $('status').innerHTML = `<span class="dot bad"></span>后端未连接：${esc(e.message)}`;
  }
  loadProjects().then(() => { autoSelectProject(); renderProjects(); updateProjectHeader(); loadFindings(); loadFacts(); });
  loadTools();
}

/* ---------- 模型切换 ---------- */
async function loadModels() {
  try {
    const d = await api('/api/models');
    state.models = d;
    renderModelSelect();
  } catch (e) { /* 后端未连接时静默 */ }
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
    log(`模型已切换：${d.current}（${d.model}），下一个任务生效`, 'c-ok');
  } catch (e) {
    log(`模型切换失败：${e.message}`, 'c-err');
    loadModels();
  }
}

/* ---------- 项目 ---------- */
let editingProject = null;
let pendingDelete = null;

function persistCurrent() {
  try { localStorage.setItem('src_current_project', state.currentProject || ''); } catch (e) {}
}

function autoSelectProject() {
  if (!state.projects.length) { state.currentProject = null; persistCurrent(); return; }
  const ids = new Set(state.projects.map(p => p.id));
  let want = '';
  try { want = localStorage.getItem('src_current_project') || ''; } catch (e) {}
  state.currentProject = (want && ids.has(want)) ? want : state.projects[0].id;
  persistCurrent();
}

function updateProjectHeader() {
  const p = state.projects.find(x => x.id === state.currentProject);
  $('currentProjectName').textContent = p ? p.name : '未选择项目';
  $('currentProjectTarget').textContent = p ? (p.target || '') : '';
}

async function loadProjects() {
  const d = await api('/api/projects');
  state.projects = d.items;
  renderProjects();
}

function renderProjects() {
  const el = $('projectList');
  if (!state.projects.length) {
    el.innerHTML = '<div class="empty">还没有项目，先建一个</div>';
    return;
  }
  el.innerHTML = state.projects.map(p => {
    if (editingProject === p.id) {
      return `<div class="list-item active">
        <div class="row" style="margin-bottom:4px;"><input id="editPName" value="${esc(p.name)}" placeholder="项目名称"></div>
        <div class="row"><input id="editPTarget" value="${esc(p.target || '')}" placeholder="目标：企业名 / 域名"></div>
        <div style="display:flex;gap:6px;">
          <button class="primary sm" onclick="submitEditProject('${p.id}')">保存</button>
          <button class="sm" onclick="cancelEditProject()">取消</button>
        </div>
      </div>`;
    }
    if (pendingDelete === p.id) {
      return `<div class="list-item active" style="border-color:rgba(248,113,113,.4);background:rgba(248,113,113,.08);">
        <div class="name">删除「${esc(p.name)}」？</div>
        <div class="meta">漏洞记录、已证事实与会话将一并删除，不可恢复。</div>
        <div class="item-actions" style="display:flex;">
          <button class="danger" onclick="event.stopPropagation();removeProject('${p.id}')">确认删除</button>
          <button onclick="event.stopPropagation();pendingDelete=null;renderProjects()">取消</button>
        </div>
      </div>`;
    }
    return `<div class="list-item ${state.currentProject === p.id ? 'active' : ''}"
         onclick="selectProject('${p.id}')">
      <div class="name">${esc(p.name)}</div>
      <div class="meta">${esc(p.target || '无目标')} · 漏洞 ${p.finding_count}</div>
      <div class="item-actions">
        <button onclick="event.stopPropagation();startEditProject('${p.id}')">重命名</button>
        <button class="danger" onclick="event.stopPropagation();askDeleteProject('${p.id}')">删除</button>
      </div>
    </div>`;
  }).join('');
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
  persistCurrent();
  await loadProjects();
  updateProjectHeader();
  loadFindings();
  loadFacts();
}

async function selectProject(pid) {
  state.currentProject = pid;
  persistCurrent();
  renderProjects();
  updateProjectHeader();
  loadFindings();
  loadFacts();
}

function startEditProject(pid) {
  editingProject = pid;
  pendingDelete = null;
  renderProjects();
  const el = $('editPName');
  if (el) el.focus();
}

function cancelEditProject() {
  editingProject = null;
  renderProjects();
}

async function submitEditProject(pid) {
  const name = $('editPName').value.trim();
  if (!name) return alert('项目名称不能为空');
  await api(`/api/projects/${pid}`, {
    method: 'PUT',
    body: JSON.stringify({ name, target: $('editPTarget').value.trim() }),
  });
  editingProject = null;
  await loadProjects();
  updateProjectHeader();
  log('项目已保存修改', 'c-ok');
}

function askDeleteProject(pid) {
  pendingDelete = pid;
  editingProject = null;
  renderProjects();
}

async function removeProject(pid) {
  await api(`/api/projects/${pid}`, { method: 'DELETE' });
  pendingDelete = null;
  if (state.currentProject === pid) {
    state.currentProject = null;
    $('findingList').innerHTML = '<div class="empty">暂无记录</div>';
    $('factList').innerHTML = '<div class="empty">暂无已证事实</div>';
    $('factCount').textContent = '0';
  }
  await loadProjects();
  autoSelectProject();
  renderProjects();
  updateProjectHeader();
  log('项目已删除', 'c-ok');
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
    log(r.ok ? `已启动：${r.message}` : `启动失败：${r.message}`, r.ok ? 'c-ok' : 'c-err');
  } catch (e) {
    log(`启动失败：${e.message}`, 'c-err');
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
  state.assistant = null;

  if (state.currentProject && !state.projects.some(p => p.id === state.currentProject)) {
    autoSelectProject();
    renderProjects();
    updateProjectHeader();
  }
  if (!state.currentProject) {
    if (state.projects.length) {
      autoSelectProject();
      renderProjects();
      updateProjectHeader();
    } else {
      log('还没有项目：请先在左侧「新建项目」并填写目标，Agent 才能识别扫描对象', 'c-warn');
      $('sendBtn').disabled = false;
      return;
    }
  }
  const proj = state.projects.find(p => p.id === state.currentProject);
  if (proj && !proj.target) {
    log(`项目「${proj.name}」未填写目标，模型可能无法识别扫描对象（可在项目上点「重命名」补填）`, 'c-warn');
  }

  // 先渲染用户气泡 + AI 气泡，再发起任务
  addUserMessage(msg);
  createAssistant();

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
      setAssistantMeta(`会话 ${ev.session_id}`);
      break;
    case 'model':
      setAssistantMeta(`${ev.data.label} · ${ev.data.model}`);
      break;
    case 'target':
      addTargetTag(ev.data);
      break;
    case 'thinking':
      setAssistantStatus(ev.data);
      break;
    case 'reasoning':
      appendReasoning(md(ev.data));
      break;
    case 'command':
      appendCommand(ev.data);
      break;
    case 'output':
      appendOutput(ev.data);
      break;
    case 'exit':
      appendLine(`退出码 ${ev.code}`, ev.code === 0 ? 'muted' : 'err');
      break;
    case 'step_start':
    case 'step_done':
    case 'step_denied':
      upsertStep(ev.step);
      break;
    case 'error':
      appendLine(ev.data, 'err');
      break;
    case 'need_confirm':
      showConfirm(ev);
      break;
    case 'answer':
      appendAnswer(md(ev.data));
      break;
    case 'done':
      finalizeAssistant(ev.state, state.steps.length);
      $('sendBtn').disabled = false;
      state.eventSource.close();
      if (state.currentProject) { loadFindings(); loadFacts(); }
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
  const a = state.assistant; if (!a) return;
  const el = a.stepsEl;
  if (!state.steps.length) { el.style.display = 'none'; return; }
  el.style.display = 'block';
  el.innerHTML = `<div class="steps-title">执行计划 · ${state.steps.length} 步</div>` +
    state.steps.map((s, i) => `
      <div class="step-chip">
        <span class="idx">${i + 1}</span>
        <span class="badge ${s.risk.level}">${s.risk.level}</span>
        <span class="t">${esc(s.tool_name)} → ${esc(s.target || '')}</span>
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
  appendLine(approved ? '→ 已放行' : '→ 已拒绝', approved ? '' : 'err');
  await api(`/api/sessions/${state.sessionId}/confirm`, {
    method: 'POST',
    body: JSON.stringify({ approved }),
  });
}

/* ---------- 右侧面板折叠 ---------- */
function toggleRight() {
  const p = $('rightPanel');
  const closed = p.classList.toggle('closed');
  document.querySelector('.app').classList.toggle('right-closed', closed);
  $('toggleRightBtn').textContent = closed ? '报告 ◂' : '报告 ▸';
}

/* ---------- 漏洞发现 ---------- */
function toggleFindingForm() {
  const el = $('findingForm');
  el.style.display = el.style.display === 'none' ? 'flex' : 'none';
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

/* ---------- 已证事实 ---------- */
function toggleFactForm() {
  const el = $('factForm');
  el.style.display = el.style.display === 'none' ? 'flex' : 'none';
}

async function loadFacts() {
  if (!state.currentProject) return;
  const d = await api(`/api/projects/${state.currentProject}`);
  renderFacts(d.facts || []);
}

function renderFacts(facts) {
  $('factCount').textContent = facts.length;
  const el = $('factList');
  if (!facts.length) {
    el.innerHTML = '<div class="empty">暂无已证事实</div>';
    return;
  }
  el.innerHTML = facts.map(f => `
    <div class="finding">
      <div class="ftitle">${esc(f.content)} <span class="badge ${f.source === 'agent' ? '' : 'off'}">${f.source === 'agent' ? 'Agent' : '人工'}</span></div>
      <div class="fmeta"><button class="sm danger" onclick="delFact('${f.id}')">删除</button></div>
    </div>`).join('');
}

async function addFact() {
  if (!state.currentProject) return alert('请先选择项目');
  const content = $('factContent').value.trim();
  if (!content) return alert('请填写事实内容');
  await api(`/api/projects/${state.currentProject}/facts`, {
    method: 'POST',
    body: JSON.stringify({ content }),
  });
  $('factContent').value = '';
  toggleFactForm();
  loadFacts();
}

async function delFact(fid) {
  await api(`/api/projects/${state.currentProject}/facts/${fid}`, { method: 'DELETE' });
  loadFacts();
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
  log(`报告已导出至 ${d.path}`, 'c-ok');
}

/* ---------- 设置 · 通用 LLM 供应商管理 ---------- */
let prov = { items: [], current: 'ollama', auto_route: true, auto_route_id: 'deepseek', presets: [] };
let editingProvider = null;

async function openSettings() {
  $('settingsModal').style.display = 'flex';
  editingProvider = null;
  $('providerForm').style.display = 'none';
  await loadPresets();
  await loadProviders();
}

function closeSettings() {
  $('settingsModal').style.display = 'none';
}

async function loadPresets() {
  if (prov.presets.length) return;
  try {
    const d = await api('/api/llm/presets');
    prov.presets = d.items;
    $('presetSelect').innerHTML = d.items.map(p =>
      `<option value="${esc(p.key)}">${esc(p.name)}${p.note ? ' — ' + esc(p.note) : ''}</option>`
    ).join('');
  } catch (e) { /* 静默 */ }
}

async function loadProviders() {
  try {
    const d = await api('/api/llm/providers');
    prov.items = d.items;
    prov.current = d.current;
    prov.auto_route = d.auto_route;
    prov.auto_route_id = d.auto_route_id;
    $('storeFileTip').textContent = d.store_file || '';
    renderProviders();
  } catch (e) {
    $('providerList').innerHTML = `<div class="empty">读取失败：${esc(e.message)}</div>`;
  }
}

function renderProviders() {
  const box = $('providerList');
  if (!prov.items.length) {
    box.innerHTML = '<div class="empty">还没有供应商，从上方模板添加一个</div>';
  } else {
    box.innerHTML = prov.items.map(p => {
      const tag = p.local
        ? '<span class="badge L0">本地</span>'
        : (p.type === 'anthropic' ? '<span class="badge gui">Anthropic</span>'
                                  : '<span class="badge L1">OpenAI</span>');
      const cur = p.id === prov.current ? '<span class="badge L1">使用中</span>' : '';
      const off = !p.enabled ? '<span class="badge off">已停用</span>' : '';
      const key = p.local ? '' : (p.has_key
        ? `<span class="badge">${esc(p.key_masked)}</span>`
        : '<span class="badge off">未填 Key</span>');
      const isCur = p.id === prov.current;
      return `<div class="prov-item ${isCur ? 'current' : ''}">
        <div class="pinfo">
          <div class="pname">${esc(p.name)}${tag}${cur}${off}</div>
          <div class="pmeta">${esc(p.model || '未填模型')} · ${esc(p.base_url || '未填端点')} ${key}</div>
        </div>
        <div class="pacts">
          <button class="sm" onclick="useProvider('${p.id}')" ${isCur ? 'disabled' : ''}>${isCur ? '使用中' : '启用'}</button>
          <button class="sm" onclick="testProvider('${p.id}')">测试</button>
          <button class="sm" onclick="openProviderForm('${p.id}')">编辑</button>
          ${p.builtin
            ? `<button class="sm" onclick="resetProvider('${p.id}')">恢复默认</button>`
            : `<button class="sm danger" onclick="deleteProvider('${p.id}')">删除</button>`}
        </div>
      </div>`;
    }).join('');
  }

  $('autoRouteChk').checked = !!prov.auto_route;
  $('autoRouteSel').innerHTML = prov.items.filter(p => !p.local).map(p =>
    `<option value="${esc(p.id)}" ${p.id === prov.auto_route_id ? 'selected' : ''}>${esc(p.name)}</option>`
  ).join('') || '<option value="">（无云端供应商）</option>';
}

function openProviderForm(id) {
  editingProvider = id;
  $('providerForm').style.display = 'block';
  $('pfModelPick').style.display = 'none';
  $('pfState').textContent = '';
  const p = id ? prov.items.find(x => x.id === id) : null;
  $('pfName').value = p ? p.name : '';
  $('pfType').value = p ? p.type : 'openai';
  $('pfBase').value = p ? p.base_url : '';
  $('pfKey').value = '';
  $('pfModel').value = p ? p.model : '';
  $('pfThinking').checked = p ? !!p.thinking : false;
  $('pfLocal').checked = p ? !!p.local : false;
  $('pfDisabled').checked = p ? !p.enabled : false;
  $('pfTimeout').value = p && p.timeout ? p.timeout : '';
  onProviderTypeChange();
  $('pfName').focus();
}

function closeProviderForm() {
  editingProvider = null;
  $('providerForm').style.display = 'none';
}

function onProviderTypeChange() {
  const isAnth = $('pfType').value === 'anthropic';
  $('pfBase').placeholder = isAnth
    ? 'Base URL，如 https://api.anthropic.com'
    : 'Base URL，如 https://api.deepseek.com/v1';
}

async function saveProviderForm() {
  const body = {
    id: editingProvider || '',
    name: $('pfName').value.trim(),
    type: $('pfType').value,
    base_url: $('pfBase').value.trim(),
    api_key: $('pfKey').value.trim(),
    model: $('pfModel').value.trim(),
    thinking: $('pfThinking').checked,
    local: $('pfLocal').checked,
    enabled: !$('pfDisabled').checked,
  };
  const t = parseInt($('pfTimeout').value, 10);
  if (t > 0) body.timeout = t;

  if (!body.name) return alert('请填写供应商名称');
  if (!body.base_url) return alert('请填写 Base URL');
  if (!body.model) return alert('请填写模型名');
  if (!body.local && !body.api_key && !editingProvider) return alert('云端供应商请填写 API Key');

  try {
    const r = await api('/api/llm/providers', { method: 'POST', body: JSON.stringify(body) });
    $('pfKey').value = '';
    editingProvider = r.provider.id;
    $('pfState').textContent = '已保存，可点列表里的「测试」验证连通性与工具调用能力。';
    await loadProviders();
    loadModels();
    log(`供应商「${r.provider.name}」已保存`, 'c-ok');
  } catch (e) {
    $('pfState').textContent = `保存失败：${e.message}`;
  }
}

async function addFromPreset() {
  const preset = prov.presets.find(p => p.key === $('presetSelect').value);
  if (!preset) return;
  const exist = prov.items.find(p => p.id === preset.key);
  if (exist) { openProviderForm(exist.id); return; }
  try {
    const r = await api('/api/llm/providers', {
      method: 'POST',
      body: JSON.stringify({
        name: preset.name, type: preset.type, base_url: preset.base_url,
        model: preset.model, local: !!preset.local, thinking: !!preset.thinking,
        api_key: '', enabled: true,
      }),
    });
    await loadProviders();
    loadModels();
    openProviderForm(r.provider.id);
    $('pfState').textContent = '模板已创建，填写 API Key 后「保存」→「测试」。';
  } catch (e) {
    alert('添加失败：' + e.message);
  }
}

async function useProvider(id) {
  try {
    await api(`/api/llm/providers/${id}/use`, { method: 'POST', body: JSON.stringify({ id }) });
    await loadProviders();
    loadModels();
    log(`决策供应商已切换：${id}`, 'c-ok');
  } catch (e) {
    alert('切换失败：' + e.message);
  }
}

async function saveAutoRoute() {
  const id = prov.current || 'ollama';
  try {
    await api(`/api/llm/providers/${id}/use`, {
      method: 'POST',
      body: JSON.stringify({
        id,
        auto_route: $('autoRouteChk').checked,
        auto_route_id: $('autoRouteSel').value,
      }),
    });
    prov.auto_route = $('autoRouteChk').checked;
    prov.auto_route_id = $('autoRouteSel').value;
    log(`自动路由${prov.auto_route ? '已开启 → ' + prov.auto_route_id : '已关闭'}`, 'c-ok');
  } catch (e) {
    alert('保存失败：' + e.message);
  }
}

async function testProvider(id) {
  const p = prov.items.find(x => x.id === id);
  log(`正在探测「${p ? p.name : id}」…`, 'c-mute');
  try {
    const r = await api(`/api/llm/providers/${id}/test`, { method: 'POST' });
    if (r.error) {
      log(`测试失败：${r.error}`, 'c-err');
      alert('连接失败：\n' + r.error);
      return;
    }
    log(`测试「${p ? p.name : id}」：对话 ${r.chat ? '✓' : '✗'} · 工具调用 ${r.tools ? '✓' : '✗'} · 可用模型 ${r.models.length} 个`, r.chat ? 'c-ok' : 'c-err');
    if (r.hint) log(`提示：${r.hint}`, 'c-warn');
    if (r.models.length) {
      const pick = $('pfModelPick');
      pick.innerHTML = `<option value="">— 选择模型（${r.models.length}）—</option>`
        + r.models.map(m => `<option value="${esc(m)}">${esc(m)}</option>`).join('');
      pick.style.display = 'block';
    }
  } catch (e) {
    log(`测试请求失败：${e.message}`, 'c-err');
  }
}

async function fetchProviderModels() {
  if (!editingProvider) return alert('请先「保存」该供应商，再拉取模型列表');
  try {
    const r = await api(`/api/llm/providers/${editingProvider}/models`);
    if (!r.ok || !r.models.length) {
      $('pfState').textContent = '未能拉取：' + (r.error || '该端点未开放 /models 接口，请手动填写模型名');
      return;
    }
    const pick = $('pfModelPick');
    pick.innerHTML = `<option value="">— 选择模型（${r.models.length}）—</option>`
      + r.models.map(m => `<option value="${esc(m)}">${esc(m)}</option>`).join('');
    pick.style.display = 'block';
    $('pfState').textContent = `已拉取 ${r.models.length} 个模型，选中后自动填入模型名。`;
  } catch (e) {
    $('pfState').textContent = '拉取失败：' + e.message;
  }
}

async function deleteProvider(id) {
  const p = prov.items.find(x => x.id === id);
  if (!confirm(`删除供应商「${p ? p.name : id}」？`)) return;
  try {
    await api(`/api/llm/providers/${id}`, { method: 'DELETE' });
    if (editingProvider === id) closeProviderForm();
    await loadProviders();
    loadModels();
    log(`已删除供应商：${id}`, 'c-ok');
  } catch (e) {
    alert('删除失败：' + e.message);
  }
}

async function resetProvider(id) {
  if (!confirm('恢复默认会清空已填的 Key 与端点，确认？')) return;
  await api(`/api/llm/providers/${id}/reset`, { method: 'POST' });
  await loadProviders();
  loadModels();
  log(`已恢复默认：${id}`, 'c-ok');
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

$('settingsModal').addEventListener('click', e => {
  if (e.target.id === 'settingsModal') closeSettings();
});

init();
