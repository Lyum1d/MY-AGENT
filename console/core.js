/* 配置控制台内核（v050）：登录闸门 / 视图路由 / 请求 / 弹窗 / 提示 / 小工具。
 *
 * 零构建、原生 ES module。改完刷新即生效，无 node 依赖。
 * 设计约束（与项目其它部分一致）：
 *   · 不引第三方库、不引 CDN —— 本机有代理且可能离线，外联资源会直接坏掉；
 *   · 图表用自绘 SVG（现有 graph.js 已是先例）。
 */

const API = '/api/console';

/* ============================================================ 请求 */
export async function api(path, { method = 'GET', body = null } = {}) {
  const opt = { method, headers: {}, credentials: 'same-origin' };
  if (body !== null) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(API + path, opt);
  } catch (e) {
    // 网络层失败：控制台自己的提示要「说出来」，否则界面静默空着
    // （与现有 web/ 的 test_appjs.js 所守的同一类行为）
    toast('后端未连接：' + e.message, 'err');
    throw e;
  }
  let data = null;
  try { data = await res.json(); } catch (e) { data = null; }
  if (!res.ok) {
    const detail = (data && (data.detail || data.message)) || `HTTP ${res.status}`;
    const err = new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    err.status = res.status;
    err.data = data;
    if (res.status === 401) { showLogin('登录已过期，请重新登录。'); }
    throw err;
  }
  return data;
}

/* ============================================================ 提示 */
export function toast(msg, kind = '') {
  const host = document.getElementById('toastHost');
  const el = document.createElement('div');
  el.className = 'toast ' + kind;
  el.textContent = msg;
  host.appendChild(el);
  setTimeout(() => el.remove(), kind === 'err' ? 7000 : 3200);
}

/* ============================================================ 弹窗 */
let _modalResolve = null;

export function modal({ title, bodyHtml, okText = '确认提交', okClass = 'danger',
                       requireAck = false, ackText = '我确认以上改动', showOk = true }) {
  const mask = document.getElementById('modalMask');
  document.getElementById('modalTitle').textContent = title;
  document.getElementById('modalBody').innerHTML = bodyHtml;
  const ok = document.getElementById('modalOk');
  const ackWrap = document.getElementById('modalAckWrap');
  const ack = document.getElementById('modalAck');
  ok.textContent = okText;
  ok.className = okClass;
  ok.hidden = !showOk;
  ackWrap.hidden = !requireAck;
  document.getElementById('modalAckText').textContent = ackText;
  ack.checked = false;
  const sync = () => { ok.disabled = requireAck && !ack.checked; };
  ack.onchange = sync;
  sync();
  mask.hidden = false;
  return new Promise((resolve) => { _modalResolve = resolve; });
}

function _closeModal(result) {
  document.getElementById('modalMask').hidden = true;
  const r = _modalResolve; _modalResolve = null;
  if (r) r(result);
}

export function bindModal() {
  document.getElementById('modalX').onclick = () => _closeModal(false);
  document.getElementById('modalCancel').onclick = () => _closeModal(false);
  document.getElementById('modalOk').onclick = () => _closeModal(true);
}

/* ============================================================ 小工具 */
/* 纯函数从 lib.js 再导出 —— 拆出去是为了让 Node 能直接 import 做行为测试
 * （DOM 相关的东西留在本文件，纯逻辑在 lib.js）。视图层仍从 core.js 取。 */
export { esc, fmtTime, alertBox, diffHtml, parseList } from '/console-assets/lib.js?v=0502';

/* ============================================================ 登录 */
export function showLogin(msg) {
  document.getElementById('loginMask').hidden = false;
  document.getElementById('appRoot').hidden = true;
  if (msg) document.getElementById('loginMsg').textContent = msg;
}

function hideLogin() {
  document.getElementById('loginMask').hidden = true;
  document.getElementById('appRoot').hidden = false;
}

async function doLogin() {
  const pw = document.getElementById('pw').value;
  const msg = document.getElementById('loginMsg');
  msg.textContent = '';
  try {
    await api('/login', { method: 'POST', body: { password: pw } });
    document.getElementById('pw').value = '';
    await boot();
  } catch (e) {
    msg.textContent = e.message;
  }
}

/* ============================================================ 视图路由 */
const VIEWS = {
  overview: () => import('/console-assets/views/overview.js?v=0502'),
  scope:    () => import('/console-assets/views/scope.js?v=0502'),
  tools:    () => import('/console-assets/views/tools.js?v=0502'),
  params:   () => import('/console-assets/views/params.js?v=0502'),
  rules:    () => import('/console-assets/views/rules.js?v=0502'),
  monitor:  () => import('/console-assets/views/monitor.js?v=0502'),
  charts:   () => import('/console-assets/views/charts.js?v=0502'),
  audit:    () => import('/console-assets/views/audit.js?v=0502'),
};
const TITLES = {
  overview: '总览', scope: '授权白名单', tools: '工具与分级', params: '运行参数',
  rules: '合规与模板', monitor: '实时监控', charts: '统计看板', audit: '合规审计',
};

let current = '';

export async function goto(view) {
  if (!VIEWS[view]) view = 'overview';
  current = view;
  document.querySelectorAll('#tabs .tab').forEach((b) => {
    b.classList.toggle('active', b.dataset.view === view);
  });
  document.getElementById('viewTitle').textContent = TITLES[view] || view;
  const host = document.getElementById('viewHost');
  host.innerHTML = '<div class="empty">正在加载…</div>';
  try {
    const mod = await VIEWS[view]();
    host.innerHTML = '';
    await mod.render(host);
  } catch (e) {
    // 面板加载失败必须「说出来」。这条是刻意保留的行为：
    // 后端没有某个接口时（404）若只是静默空着，用户会以为功能坏了。
    host.innerHTML = `<div class="alert high"><span class="ico">!</span>`
      + `<span>该面板加载失败：${esc(e.message)}</span></div>`
      + `<div class="hint">若是 404，说明后端未注册该接口（可能版本不匹配）。</div>`;
  }
}

export function reload() { return goto(current); }

/* ============================================================ 启动 */
export async function boot() {
  let s;
  try {
    s = await api('/session');
  } catch (e) {
    showLogin('无法读取会话状态：' + e.message);
    return;
  }
  if (!s.password_configured) {
    showLogin('控制台口令未设置。请在环境变量 AGENT_CONSOLE_PASSWORD '
            + '或本机 config.yaml 的 consolePassword 中设置后重启服务。');
    return;
  }
  if (!s.authenticated) { showLogin(''); return; }

  hideLogin();
  document.getElementById('whoami').textContent = '已登录 · 仅本机';
  await goto('overview');
}

export function setFileHint(text) {
  document.getElementById('fileHint').textContent = text || '';
}

function initGlobal() {
  bindModal();
  document.getElementById('loginBtn').onclick = doLogin;
  document.getElementById('pw').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doLogin();
  });
  document.getElementById('logoutBtn').onclick = async () => {
    try { await api('/logout', { method: 'POST' }); } catch (e) { /* 忽略 */ }
    showLogin('已退出登录。');
  };
  document.getElementById('themeBtn').onclick = () => {
    const cur = document.documentElement.getAttribute('data-theme') || 'dark';
    const next = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('src_theme', next); } catch (e) { /* 忽略 */ }
  };
  document.getElementById('tabs').addEventListener('click', (e) => {
    const b = e.target.closest('.tab');
    if (b) goto(b.dataset.view);
  });
}

initGlobal();
boot();
