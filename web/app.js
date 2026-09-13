/* SRC 渗透 Agent 控制台前端 — 对话式界面 */

let state = {
  projects: [],
  currentProject: null,
  sessionId: null,
  threadFresh: true,   // 当前聊天区是否还是「没发过消息」的空线程（true=发送时复用 sessionId）
  tree: [],            // 当前项目的线索树
  eventSource: null,
  tools: [],
  steps: [],
  models: null,
  assistant: null,   // 当前 AI 气泡的 DOM 引用（streaming 时填充）
  branchParent: null, // 开分支弹窗的父会话 id
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
  loadProjects().then(() => { autoSelectProject(); renderProjects(); updateProjectHeader(); loadFindings(); loadFacts(); loadTree(); });
  loadTools();
  refreshUsageBadge();
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
  loadTree();
}

async function selectProject(pid) {
  state.currentProject = pid;
  persistCurrent();
  renderProjects();
  updateProjectHeader();
  loadFindings();
  loadFacts();
  // 切项目 = 切对话树：清空当前线程，聊天区回到空态
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
  state.sessionId = null;
  state.threadFresh = true;
  state.steps = [];
  state.assistant = null;
  $('confirmBox').innerHTML = '';
  $('messages').innerHTML = `
    <div class="welcome" id="welcome">
      <div class="welcome-logo">🛡</div>
      <div class="welcome-title">SRC 渗透测试编排助手</div>
      <div class="welcome-sub">已切换项目。描述你的任务开始测试；发现可疑点可随时「＋ 分支」拆出新线索。</div>
    </div>`;
  loadTree();
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
  loadTree();
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

  // 同一线索内连续发消息 = 续聊（上下文累积，便于对一个方向深挖）；
  // 新建对话或刚切换进来的已有线索，threadFresh 标记是否需要复用。
  let sid;
  if (state.sessionId && state.threadFresh) {
    sid = state.sessionId;
  } else {
    const s = await api('/api/sessions', {
      method: 'POST',
      body: JSON.stringify({ project_id: state.currentProject || '' }),
    });
    sid = s.session_id;
    state.threadFresh = false;
  }
  state.sessionId = sid;

  await api(`/api/sessions/${sid}/run`, {
    method: 'POST',
    body: JSON.stringify({ message: msg, project_id: state.currentProject || '' }),
  });

  connectStream(sid);
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
    case 'branch_proposal':
      showBranchCard(ev.data);
      break;
    case 'branch_update':
      log(`子线索「${ev.data.title}」有新结论：${ev.data.summary.slice(0, 80)}…（已可在报告/小地图查看）`, 'c-ok');
      loadTree();
      break;
    case 'answer':
      appendAnswer(md(ev.data));
      break;
    case 'done':
      finalizeAssistant(ev.state, state.steps.length);
      $('sendBtn').disabled = false;
      state.eventSource.close();
      state.threadFresh = false;
      if (state.currentProject) { loadFindings(); loadFacts(); loadTree(); }
      refreshUsageBadge();
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

/* ---------- 线索树（对话树小地图） ---------- */
const THREAD_STATUS_LABEL = { active: '进行中', done: '已完成', abandoned: '已放弃' };

async function loadTree() {
  if (!state.currentProject) { $('treeBar').style.display = 'none'; return; }
  try {
    const d = await api(`/api/projects/${state.currentProject}/tree`);
    state.tree = d.items;
    $('treeBar').style.display = 'flex';
    renderTree();
  } catch (e) { /* 树加载失败不打断聊天 */ }
}

function threadName(n) {
  return n.title || (n.task || '').slice(0, 18) || '未命名对话';
}

function renderTree() {
  const strip = $('treeStrip');
  if (!state.tree.length) {
    strip.innerHTML = '<div class="tree-empty">同一方向聊久了会遗忘细节——发现可疑点就「＋ 分支」拆出独立线索深挖</div>';
    return;
  }
  const byParent = {};
  state.tree.forEach(n => (byParent[n.parent_id || ''] = byParent[n.parent_id || ''] || []).push(n));
  const depthOf = {};
  const walk = (pid, d) => (byParent[pid] || []).forEach(n => {
    depthOf[n.id] = d;
    walk(n.id, d + 1);
  });
  walk('', 0);
  const maxDepth = Math.max(0, ...Object.values(depthOf));

  strip.innerHTML = Array.from({ length: maxDepth + 1 }, (_, d) => {
    const nodes = state.tree.filter(n => depthOf[n.id] === d);
    return `<div class="tree-col">
      ${nodes.map(n => {
        const isCur = n.id === state.sessionId;
        const st = THREAD_STATUS_LABEL[n.status] || n.status;
        return `<div class="tnode st-${esc(n.status)} ${isCur ? 'cur' : ''}" onclick="openThread('${n.id}')" title="${esc(n.task || '')}">
          <div class="tn-name">${esc(threadName(n))}</div>
          <div class="tn-meta">${st} · ${n.step_count} 步</div>
          <div class="tn-acts">
            <button onclick="event.stopPropagation();openBranchModal('${n.id}')" title="在此线索下开新分支">＋</button>
            ${n.status !== 'done' ? `<button onclick="event.stopPropagation();setThreadStatus('${n.id}','done')" title="标记已完成">✓</button>` : ''}
            ${n.status !== 'abandoned' ? `<button onclick="event.stopPropagation();setThreadStatus('${n.id}','abandoned')" title="标记已放弃">✕</button>` : ''}
            ${n.status !== 'active' ? `<button onclick="event.stopPropagation();setThreadStatus('${n.id}','active')" title="重新打开">↺</button>` : ''}
          </div>
        </div>`;
      }).join('')}
    </div>`;
  }).join('');
}

/* 切换到某条线索：恢复持久化会话并回放历史 */
async function openThread(sid) {
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
  $('sendBtn').disabled = false;
  $('confirmBox').innerHTML = '';
  try {
    await api('/api/sessions', { method: 'POST', body: JSON.stringify({ sid }) });
  } catch (e) { return alert('切换失败：' + e.message); }
  state.sessionId = sid;
  state.threadFresh = false;
  const d = await api(`/api/sessions/${sid}`);
  const m = $('messages');
  m.innerHTML = '';
  state.steps = d.steps || [];
  state.assistant = null;

  const head = document.createElement('div');
  head.className = 'sys-note';
  head.textContent = `线索「${d.title || '未命名对话'}」 · ${state.steps.length} 条历史记录`;
  m.appendChild(head);

  (d.records || []).forEach(rec => {
    const el = document.createElement('div');
    el.className = 'sys-note thread-record';
    el.textContent = '📦 ' + rec;
    m.appendChild(el);
  });

  // 历史对话回放：有聊天记录时按原气泡样式还原（用户消息 / AI 说明 / 结论）
  const chat = d.chat || [];
  if (chat.length) {
    const chatHead = document.createElement('div');
    chatHead.className = 'sys-note';
    chatHead.textContent = '—— 历史对话 ——';
    m.appendChild(chatHead);
    chat.forEach(msg => {
      if (msg.role === 'user') {
        addUserMessage(msg.content);
      } else {
        if (!state.assistant) createAssistant();
        if (msg.kind === 'answer') appendAnswer(md(msg.content));
        else appendReasoning(md(msg.content));
      }
    });
    state.assistant = null;
  } else {
    // 旧会话无聊天记录：回退为步骤清单 + 结论摘要
    state.steps.forEach(s => {
      appendLine(`• ${s.tool_name || s.tool_alias} → ${s.target || '-'} [${s.status}]`, 'muted');
    });
    if (d.summary) appendAnswer(md(d.summary));
  }
  if (d.state === 'running' || d.state === 'awaiting_confirm') {
    connectStream(sid);
    log('该线索正在执行中，已接入实时输出…', 'c-warn');
  }
  renderTree();
  scrollToBottom();
}

/* 另起一条独立主对话 */
function newThread() {
  if (state.eventSource) { state.eventSource.close(); state.eventSource = null; }
  state.sessionId = null;
  state.threadFresh = true;
  state.steps = [];
  state.assistant = null;
  $('sendBtn').disabled = false;
  $('confirmBox').innerHTML = '';
  $('messages').innerHTML = `
    <div class="welcome" id="welcome">
      <div class="welcome-logo">🛡</div>
      <div class="welcome-title">新的对话</div>
      <div class="welcome-sub">描述你的任务开始。发送后它会作为一条主对话出现在上方线索树里。</div>
    </div>`;
  renderTree();
}

async function setThreadStatus(sid, status) {
  try {
    await api(`/api/sessions/${sid}/meta`, {
      method: 'PUT',
      body: JSON.stringify({ status }),
    });
    loadTree();
  } catch (e) { alert('状态更新失败：' + e.message); }
}

/* 开分支弹窗：候选记录 = 该线索最近的执行步骤 */
async function openBranchModal(sid) {
  state.branchParent = sid || state.sessionId;
  if (!state.branchParent) {
    return log('还没有可分叉的对话：先发送一个任务，或在线索树里选中一条线索', 'c-warn');
  }
  $('bTitle').value = '';
  $('bNote').value = '';
  $('branchState').textContent = '';
  let steps = [];
  try {
    const d = await api(`/api/sessions/${state.branchParent}`);
    steps = d.steps || [];
  } catch (e) { /* 忽略，保留空候选 */ }
  const cands = steps.slice(-8).reverse();
  $('branchCandidates').innerHTML = cands.length
    ? cands.map((c, i) => `
      <label class="bc-cand">
        <input type="checkbox" value="${esc(c.id)}" ${i < 3 ? 'checked' : ''}>
        <span class="bc-cand-t">${esc(c.tool_name || c.tool_alias)} → ${esc(c.target || '-')}</span>
        <span class="bc-cand-o">${esc((c.output || '').replace(/\s+/g, ' ').slice(0, 70))}</span>
      </label>`).join('')
    : '<div class="empty">该线索还没有执行记录，将只带走补充说明</div>';
  $('branchModal').style.display = 'flex';
}

function closeBranchModal() {
  $('branchModal').style.display = 'none';
  state.branchParent = null;
}

async function confirmCreateBranch() {
  const title = $('bTitle').value.trim();
  if (!title) return alert('请填写线索名称');
  const ids = [...$('branchCandidates').querySelectorAll('input:checked')].map(x => x.value);
  try {
    const r = await api(`/api/sessions/${state.branchParent}/branch`, {
      method: 'POST',
      body: JSON.stringify({ title, record_ids: ids, extra_note: $('bNote').value.trim() }),
    });
    closeBranchModal();
    log(`已创建线索「${r.title}」，携带 ${r.records.length} 条记录`, 'c-ok');
    await loadTree();
    openThread(r.session_id);
  } catch (e) {
    $('branchState').textContent = '创建失败：' + e.message;
  }
}

/* AI 建议开线索的卡片（propose_branch 事件触发） */
function showBranchCard(data) {
  clearWelcome();
  const m = $('messages');
  const card = document.createElement('div');
  card.className = 'branch-card';
  card.innerHTML = `
    <div class="bc-title">🌱 建议开辟新线索：《${esc(data.title)}》</div>
    ${data.reason ? `<div class="bc-reason">${md(data.reason)}</div>` : ''}
    <div class="bc-tip">新线索会带上你勾选的记录独立深挖这个方向，当前对话不受影响：</div>
    <div class="bc-cands">
      ${(data.candidates || []).map(c => `
        <label class="bc-cand">
          <input type="checkbox" value="${esc(c.id)}" checked>
          <span class="bc-cand-t">${esc(c.tool_name || c.tool_alias)} → ${esc(c.target || '-')}</span>
          <span class="bc-cand-o">${esc((c.output || '').replace(/\s+/g, ' ').slice(0, 70))}</span>
        </label>`).join('') || '<div class="muted">（暂无可打包的执行记录，仅携带建议说明）</div>'}
    </div>
    <div class="bc-actions">
      <button class="primary sm bc-go">确认开辟并切换</button>
      <button class="sm bc-no">暂不需要</button>
    </div>`;
  m.appendChild(card);
  scrollToBottom();
  card.querySelector('.bc-go').onclick = async () => {
    const ids = [...card.querySelectorAll('input:checked')].map(x => x.value);
    try {
      const r = await api(`/api/sessions/${state.sessionId}/branch`, {
        method: 'POST',
        body: JSON.stringify({ title: data.title, record_ids: ids, extra_note: data.reason || '' }),
      });
      card.remove();
      log(`已创建线索「${r.title}」`, 'c-ok');
      await loadTree();
      openThread(r.session_id);
    } catch (e) {
      log('创建线索失败：' + e.message, 'c-err');
    }
  };
  card.querySelector('.bc-no').onclick = () => card.remove();
}

/* ---------- Token 用量统计 ---------- */
function fmtTok(n) {
  n = n || 0;
  if (n >= 10000) return (n / 10000).toFixed(1) + '万';
  return String(n);
}
function fmtCost(c) {
  return '≈ ¥' + (c || 0).toFixed(c > 0 && c < 1 ? 4 : 2);
}

/* 顶栏徽标：今日 token（任务完成后与打开弹窗时刷新） */
async function refreshUsageBadge() {
  try {
    const d = await api('/api/usage/summary');
    const b = $('usageBadge');
    if (b) b.textContent = d.today.calls ? `今日 ${fmtTok(d.today.tokens)} tok` : '';
  } catch (e) { /* 静默 */ }
}

function openUsage() {
  $('usageModal').style.display = 'flex';
  loadUsage();
  loadUsageList();
  loadPriceEditor();
}
function closeUsage() { $('usageModal').style.display = 'none'; }

async function loadUsage() {
  try {
    const [sum, daily, projects] = await Promise.all([
      api('/api/usage/summary'),
      api('/api/usage/daily?days=30'),
      api('/api/projects'),
    ]);
    // 汇总卡
    $('uTodayTok').textContent = fmtTok(sum.today.tokens) + ' tok';
    $('uTodayCost').textContent = fmtCost(sum.today.cost);
    $('uTodayCalls').textContent = `${sum.today.calls} 次调用 · 输入 ${fmtTok(sum.today.prompt)} / 输出 ${fmtTok(sum.today.completion)}`;
    $('uMonthTok').textContent = fmtTok(sum.month.tokens) + ' tok';
    $('uMonthCost').textContent = fmtCost(sum.month.cost);
    $('uMonthCalls').textContent = `${sum.month.calls} 次调用`;
    $('uTotalTok').textContent = fmtTok(sum.total.tokens) + ' tok';
    $('uTotalCost').textContent = fmtCost(sum.total.cost);
    $('uTotalCalls').textContent = `${sum.total.calls} 次调用`;
    // 占比
    renderUsageBars('uByModel', sum.by_model, sum.total.tokens);
    renderUsageBars('uByProject', sum.by_project, sum.total.tokens,
      Object.fromEntries(projects.items.map(p => [p.id, p.name])));
    // 筛选下拉
    const pSel = $('uFilterProject');
    const curP = pSel.value;
    pSel.innerHTML = '<option value="">全部项目</option>' + projects.items.map(p =>
      `<option value="${esc(p.id)}">${esc(p.name)}</option>`).join('');
    pSel.value = curP;
    const mSel = $('uFilterModel');
    const curM = mSel.value;
    mSel.innerHTML = '<option value="">全部模型</option>' + Object.keys(sum.by_model).map(k =>
      `<option value="${esc(k.split(':')[1] || k)}">${esc(k)}</option>`).join('');
    mSel.value = curM;
    // 趋势图
    renderDailyChart(daily.items);
    refreshUsageBadge();
  } catch (e) {
    log('用量加载失败：' + e.message, 'c-err');
  }
}

/* 横向占比条 */
function renderUsageBars(elId, map, total, nameMap) {
  const el = $(elId);
  const entries = Object.entries(map || {}).sort((a, b) => b[1].tokens - a[1].tokens);
  if (!entries.length) { el.innerHTML = '<div class="empty">暂无数据</div>'; return; }
  const maxTok = entries[0][1].tokens || 1;
  el.innerHTML = entries.map(([k, v]) => {
    const label = nameMap ? (nameMap[k] || (k ? k.slice(0, 8) : '未关联项目')) : k;
    const pct = total ? Math.round(v.tokens / total * 100) : 0;
    return `<div class="ubar" title="${esc(label)}：${v.tokens} tok / ${v.calls} 次 / ${fmtCost(v.cost)}">
      <div class="ubar-head"><span>${esc(label)}</span><span class="muted">${fmtTok(v.tokens)} · ${pct}% · ${fmtCost(v.cost)}</span></div>
      <div class="ubar-track"><div class="ubar-fill" style="width:${Math.max(3, Math.round(v.tokens / maxTok * 100))}%"></div></div>
    </div>`;
  }).join('');
}

/* SVG 按天柱状图（无外部依赖） */
function renderDailyChart(items) {
  const el = $('uDailyChart');
  if (!items || !items.some(d => d.tokens)) {
    el.innerHTML = '<div class="empty">暂无数据：跑一个任务后这里会出现按天趋势</div>';
    return;
  }
  const W = 860, H = 180, padL = 44, padB = 22, padT = 10;
  const maxTok = Math.max(...items.map(d => d.tokens), 1);
  const bw = (W - padL - 8) / items.length;
  const bars = items.map((d, i) => {
    const h = Math.round(d.tokens / maxTok * (H - padT - padB));
    const x = padL + i * bw + 1;
    const y = H - padB - h;
    const tip = `${d.day}｜${fmtTok(d.tokens)} tok · ${d.calls} 次 · ${fmtCost(d.cost)}`;
    return `<rect x="${x}" y="${y}" width="${Math.max(1, bw - 3)}" height="${h}" rx="2"
      class="uchart-bar"><title>${esc(tip)}</title></rect>
      ${i % Math.ceil(items.length / 10) === 0 ? `<text x="${x + bw / 2}" y="${H - 6}" text-anchor="middle" class="uchart-x">${d.day}</text>` : ''}`;
  }).join('');
  const gridLines = [0.25, 0.5, 0.75, 1].map(f => {
    const y = H - padB - f * (H - padT - padB);
    return `<line x1="${padL}" y1="${y}" x2="${W - 8}" y2="${y}" class="uchart-grid"/>
      <text x="${padL - 5}" y="${y + 4}" text-anchor="end" class="uchart-y">${fmtTok(Math.round(maxTok * f))}</text>`;
  }).join('');
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid meet" style="width:100%;">${gridLines}${bars}</svg>`;
}

async function loadUsageList() {
  const pid = $('uFilterProject').value;
  const model = $('uFilterModel').value;
  const days = $('uFilterDays').value;
  const qs = new URLSearchParams({ project_id: pid, model, days, limit: '300' });
  try {
    const d = await api('/api/usage/list?' + qs.toString());
    const projNames = {};
    try {
      const projects = await api('/api/projects');
      projects.items.forEach(p => projNames[p.id] = p.name);
    } catch (e) { /* 项目名映射失败就显示 id */ }
    const tb = $('uTable').querySelector('tbody');
    if (!d.items.length) {
      tb.innerHTML = '<tr><td colspan="6" class="empty">暂无记录</td></tr>';
      return;
    }
    tb.innerHTML = d.items.map(r => {
      const t = new Date(r.ts * 1000);
      const time = `${String(t.getMonth() + 1).padStart(2, '0')}-${String(t.getDate()).padStart(2, '0')} ${String(t.getHours()).padStart(2, '0')}:${String(t.getMinutes()).padStart(2, '0')}`;
      return `<tr>
        <td>${time}</td>
        <td>${esc(projNames[r.project_id] || (r.project_id ? r.project_id.slice(0, 8) : '未关联'))}</td>
        <td>${esc(r.provider_id)} / ${esc(r.model)}</td>
        <td>${r.prompt_tokens}</td>
        <td>${r.completion_tokens}</td>
        <td>${r.duration_ms ? (r.duration_ms / 1000).toFixed(1) + 's' : '-'}</td>
      </tr>`;
    }).join('');
  } catch (e) {
    log('明细加载失败：' + e.message, 'c-err');
  }
}

/* ---------- 单价编辑 ---------- */
async function loadPriceEditor() {
  try {
    const d = await api('/api/usage/prices');
    renderPriceRows(d.items);
  } catch (e) { /* 静默 */ }
}

function renderPriceRows(prices) {
  const tb = $('uPriceTable').querySelector('tbody');
  const keys = Object.keys(prices || {}).sort();
  tb.innerHTML = keys.map(k => `
    <tr>
      <td><input class="up-key" value="${esc(k)}" style="width:100%;"></td>
      <td><input class="up-in" type="number" step="0.01" min="0" value="${prices[k].input}"></td>
      <td><input class="up-out" type="number" step="0.01" min="0" value="${prices[k].output}"></td>
      <td><button class="sm danger" onclick="this.closest('tr').remove()">删</button></td>
    </tr>`).join('') || '<tr><td colspan="4" class="empty">无单价条目，点「+ 新增单价」</td></tr>';
}

function addPriceRow(model = '', input = 0, output = 0) {
  const tb = $('uPriceTable').querySelector('tbody');
  if (tb.querySelector('.empty')) tb.innerHTML = '';
  const tr = document.createElement('tr');
  tr.innerHTML = `
    <td><input class="up-key" value="${esc(model)}" placeholder="模型名，如 qwen3.7-plus" style="width:100%;"></td>
    <td><input class="up-in" type="number" step="0.01" min="0" value="${input}"></td>
    <td><input class="up-out" type="number" step="0.01" min="0" value="${output}"></td>
    <td><button class="sm danger" onclick="this.closest('tr').remove()">删</button></td>`;
  tb.appendChild(tr);
}

async function savePrices() {
  const prices = {};
  $('uPriceTable').querySelectorAll('tbody tr').forEach(tr => {
    const k = tr.querySelector('.up-key').value.trim();
    if (!k) return;
    prices[k] = {
      input: parseFloat(tr.querySelector('.up-in').value) || 0,
      output: parseFloat(tr.querySelector('.up-out').value) || 0,
    };
  });
  try {
    await api('/api/usage/prices', { method: 'POST', body: JSON.stringify({ prices }) });
    $('uPriceState').textContent = '单价已保存，费用估算立即按新价生效。';
    loadUsage();
  } catch (e) {
    $('uPriceState').textContent = '保存失败：' + e.message;
  }
}

async function resetPrices() {
  if (!confirm('恢复默认单价表（当前修改会被覆盖）？')) return;
  try {
    const d = await api('/api/usage/prices/reset', { method: 'POST' });
    renderPriceRows(d.items);
    $('uPriceState').textContent = '已恢复默认单价。';
    loadUsage();
  } catch (e) {
    $('uPriceState').textContent = '恢复失败：' + e.message;
  }
}

/* ---------- 清空 / 导出 ---------- */
function exportUsage() {
  window.open('/api/usage/export.csv', '_blank');
}

async function clearUsageAsk() {
  const choice = prompt(
    '清理用量记录：\n输入 0 = 清空全部\n输入 N（如 30）= 只删除 N 天前的旧记录\n输入其他或取消 = 放弃', '0');
  if (choice === null) return;
  const days = parseInt(choice, 10);
  if (isNaN(days) || days < 0) return;
  if (!confirm(days === 0 ? '确定清空全部用量记录？不可恢复。' : `确定删除 ${days} 天前的用量记录？`)) return;
  try {
    const r = await api('/api/usage/clear', { method: 'POST', body: JSON.stringify({ days }) });
    log(`已清理 ${r.deleted} 条用量记录`, 'c-ok');
    loadUsage();
    loadUsageList();
    refreshUsageBadge();
  } catch (e) {
    alert('清理失败：' + e.message);
  }
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

$('usageModal').addEventListener('click', e => {
  if (e.target.id === 'usageModal') closeUsage();
});

init();
