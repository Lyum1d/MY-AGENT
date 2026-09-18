/* 用最小 DOM 桩执行 web/app.js，锁定「高危确认闸门（双闸门合并版）」前端行为：
 *
 *  1) 确认必须同时带一次性 token 与 step_id —— 后端据此拒绝陈旧/重放/伪造的确认；
 *  2) 确认框里的参数可编辑，改完点放行即按改后的参数执行（仍过服务端清洗与白名单）；
 *  3) 连点只能产生一条确认 —— 多投的那条会被**下一个**高危步骤白白消费掉，
 *     等于用户没看确认框就放行了；
 *  4) L3 勾选框未勾选时不得提交（且只在 L3 才拦）；
 *  5) L2/L3 工具被后端以 409「需要显式确认」拦下时，二次确认后才带 confirm=true 重试。
 *
 * 运行：node test_confirm_js.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const WEB = path.join(__dirname, 'web');  // 审计 P1-2：相对脚本定位，不写死他人机器路径
const SRC = fs.readFileSync(path.join(WEB, 'graph.js'), 'utf8')
  + '\n' + fs.readFileSync(path.join(WEB, 'app.js'), 'utf8');

const ok = [], fail = [];
const check = (n, c, e = '') => {
  (c ? ok : fail).push(n);
  console.log(`  [${c ? 'PASS' : 'FAIL'}] ${n}${e !== '' ? ' -> ' + e : ''}`);
};

/* ---------- 记录型伪 DOM ---------- */
const lines = [];              // appendLine 落到 assistant.bodyEl 的文本
function makeEl() {
  const el = {
    className: '', textContent: '', innerHTML: '', value: '',
    style: {}, dataset: {}, children: [],
    appendChild(c) { this.children.push(c); return c; },
    querySelectorAll: () => [],
    querySelector: () => null,
    addEventListener() {},
    remove() {},
    closest: () => null,
    getAttribute: () => 'dark',
    setAttribute() {},
    classList: { add() {}, remove() {}, toggle() {}, contains: () => false },
    scrollTop: 0, scrollHeight: 0,
    getBoundingClientRect: () => ({ left: 0, top: 0, width: 900, height: 300 }),
    getComputedTextLength: () => 60,
  };
  return el;
}
const messagesEl = makeEl();
const bodyEl = makeEl();
bodyEl.appendChild = function (child) {
  this.children.push(child);
  lines.push(child.textContent || '');
  return child;
};

const els = {};
// authChk 默认「不存在」（真实 DOM 里只有 L3 才渲染这个勾选框）。
// 桩若一律返回元素，doConfirm 会误判成「勾选框存在且未勾选」而永远拦住，
// 所以这里对这个 id 特殊处理为 null。
function byId(id) {
  if (id === 'authChk') return els.authChk || null;
  if (id === 'messages') return messagesEl;
  return els[id] || (els[id] = makeEl());
}

const requests = [];           // { url, opts }
let handler = () => ({ ok: true, json: async () => ({ ok: true }) });

const sandbox = {
  console,
  document: {
    getElementById: byId,
    querySelectorAll: () => [],
    querySelector: () => makeEl(),
    createElement: () => makeEl(),
    createElementNS: () => makeEl(),
    addEventListener() {},
    documentElement: { getAttribute: () => 'dark', setAttribute() {} },
    body: makeEl(),
  },
  fetch: (u, opts) => {
    requests.push({ url: String(u), opts: opts || {} });
    return Promise.resolve(handler(String(u), opts || {}));
  },
  localStorage: { getItem: () => '', setItem() {}, removeItem() {} },
  location: { href: '/', reload() {} },
  navigator: {},
  alert() {}, confirm: () => true,
  JSON, Promise, Error, TypeError, Object, Array, String, Number, Boolean,
  Math, Date, RegExp, Map, Set, Symbol, parseInt, parseFloat, isNaN,
  encodeURIComponent, decodeURIComponent,
};
sandbox.window = sandbox;
sandbox.addEventListener = () => {};
sandbox.globalThis = sandbox;
sandbox.setTimeout = (fn) => { try { fn(); } catch (e) {} return 1; };
sandbox.clearTimeout = () => {};
sandbox.requestAnimationFrame = (fn) => fn();
vm.createContext(sandbox);
process.on('unhandledRejection', () => {});

vm.runInContext(
  SRC + '\n;globalThis.__api = { showConfirm, doConfirm, launchTool, state };',
  sandbox, { filename: 'app.js' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const A = () => sandbox.__api;

(async () => {
  await sleep(50);
  A().state.sessionId = 'sess-1';
  A().state.assistant = { bodyEl };   // appendLine 需要 assistant 才落笔

  console.log('=== 一、确认框渲染（带步骤身份 + 令牌 + 可编辑参数）===');
  A().showConfirm({
    step: { id: 'st-abc', tool_name: 'Python代码执行', target: 'x.example.com', args: 'print(1)' },
    risk: { level: 'L3', name: '权限/横向/接管', reason: '任意代码执行', double_confirm: true },
    token: 'tok-1',
  });
  const html = els.confirmBox.innerHTML;
  check('确认框渲染出工具名与等级', /Python代码执行/.test(html) && /L3/.test(html), html.slice(0, 60));
  check('L3 渲染「书面授权」勾选框', /authChk/.test(html));
  check('确认框渲染出可编辑参数框', /id="cfmArgs"/.test(html) && /class="cfm-args"/.test(html));
  check('一次性令牌被登记到 state.pendingConfirm',
    A().state.pendingConfirm && A().state.pendingConfirm.token === 'tok-1',
    A().state.pendingConfirm && A().state.pendingConfirm.token);
  check('放行按钮调用 doConfirm(true)', /doConfirm\(true\)/.test(html), html.match(/onclick="[^"]*"/g));
  check('拒绝按钮调用 doConfirm(false)', /doConfirm\(false\)/.test(html));

  console.log('\n=== 二、提交必须带一次性 token + step_id ===');
  requests.length = 0;
  // L3 场景：真实 DOM 里只有 L3 才渲染授权勾选框，且此时用户已勾选
  els.authChk = { checked: true };
  els.cfmArgs = { value: 'print(1)' };          // 用户没有改参数
  await A().doConfirm(true);
  await sleep(10);
  check('只发了一条确认请求', requests.length === 1, requests.length);
  check('URL 指向 /confirm', requests[0] && requests[0].url === '/api/sessions/sess-1/confirm',
    requests[0] && requests[0].url);
  const body = JSON.parse((requests[0] && requests[0].opts.body) || '{}');
  check('body 里带 approved', body.approved === true, JSON.stringify(body));
  check('body 里带 step_id（后端据此拒绝陈旧/伪造确认）', body.step_id === 'st-abc', JSON.stringify(body));
  check('body 里带一次性 token（后端据此拒绝上一轮遗留的确认）', body.token === 'tok-1', JSON.stringify(body));
  check('L3 放行时 auth_ack=true', body.auth_ack === true, JSON.stringify(body));
  check('放行时原样回传参数', body.args === 'print(1)', JSON.stringify(body));

  console.log('\n=== 二·补、改过参数后按改后的执行 ===');
  requests.length = 0;
  // 模拟用户在参数框里改了内容（真实 DOM 里是 <textarea id="cfmArgs">）
  els.cfmArgs = { value: 'print(2)' };
  await A().doConfirm(true);
  await sleep(10);
  const body2 = JSON.parse((requests[0] && requests[0].opts.body) || '{}');
  check('改过的参数被回传（改参数 ≠ 绕闸门，仍过服务端清洗）', body2.args === 'print(2)', JSON.stringify(body2));

  console.log('\n=== 二·补、拒绝时不回传参数 ===');
  requests.length = 0;
  await A().doConfirm(false);
  await sleep(10);
  const body3 = JSON.parse((requests[0] && requests[0].opts.body) || '{}');
  check('拒绝时 approved=false', body3.approved === false, JSON.stringify(body3));
  check('拒绝时不回传参数（args=null）', body3.args === null, JSON.stringify(body3));
  check('拒绝时不要求 auth_ack', body3.auth_ack === false, JSON.stringify(body3));

  console.log('\n=== 三、连点只产生一条确认（防「预支」）===');
  requests.length = 0;
  // 让 fetch 悬停：模拟请求在途时用户又点了一下
  let release;
  handler = () => new Promise((res) => { release = () => res({ ok: true, json: async () => ({}) }); });
  const p1 = A().doConfirm(true);
  const p2 = A().doConfirm(true);   // 在途时的第二次点击
  await sleep(10);
  check('在途连点只发出 1 条请求', requests.length === 1, requests.length);
  release();
  await Promise.all([p1, p2]);
  await sleep(10);
  check('请求结束后 confirmBusy 复位（后续可正常确认）',
    A().state.confirmBusy === false, A().state.confirmBusy);

  console.log('\n=== 四、L3 未勾选书面授权不得提交 ===');
  handler = () => ({ ok: true, json: async () => ({ ok: true }) });
  requests.length = 0;
  els.authChk = { checked: false };
  let alerted = '';
  sandbox.alert = (m) => { alerted = m; };
  await A().doConfirm(true);
  await sleep(10);
  check('勾选框存在但未勾选 → 不发请求', requests.length === 0, requests.length);
  check('并且给出提示', /授权/.test(alerted), alerted);
  els.authChk = { checked: true };
  await A().doConfirm(true);
  await sleep(10);
  check('勾选后可以提交', requests.length === 1, requests.length);
  els.authChk = null;

  console.log('\n=== 四·补、非 L3 的确认不渲染勾选框、也不被它拦住 ===');
  A().showConfirm({
    step: { id: 'st-l2', tool_name: '端口扫描', target: 'x.example.com', args: '-sV' },
    risk: { level: 'L2', name: '主动探测', reason: '会留下访问日志' },
    token: 'tok-2',
  });
  requests.length = 0;
  await A().doConfirm(true);
  await sleep(10);
  check('L2 不渲染勾选框', !/authChk/.test(els.confirmBox.innerHTML));
  check('L2 直接可提交（未被勾选框拦住）', requests.length === 1, requests.length);

  console.log('\n=== 五、提交失败要说出来，且不卡住后续确认 ===');
  lines.length = 0;
  handler = () => ({ ok: false, status: 409, statusText: 'Conflict',
                     json: async () => ({ detail: '确认与当前等待的步骤不匹配' }) });
  await A().doConfirm(true);
  await sleep(10);
  check('失败信息可见', lines.some(l => /确认提交失败/.test(l)), lines.join(' | '));
  check('失败后 confirmBusy 已复位', A().state.confirmBusy === false, A().state.confirmBusy);

  console.log('\n=== 六、L2/L3 工具启动需显式确认 ===');
  handler = (url) => (url.indexOf('confirm=true') >= 0
    ? { ok: true, json: async () => ({ ok: true, message: '已启动 X' }) }
    : { ok: false, status: 409, statusText: 'Conflict',
        json: async () => ({ detail: '「X」风险等级 L3（权限/横向/接管），启动前需要显式确认：请带上 confirm=true 重试。' }) });
  requests.length = 0;
  sandbox.confirm = () => true;      // 用户点了「确定」
  await A().launchTool('ehole');
  await sleep(20);
  check('先被 409 拦下再带 confirm=true 重试（共 2 次请求）', requests.length === 2,
    requests.map(r => r.url).join(' , '));
  check('重试请求带上 confirm=true',
    requests[1] && /confirm=true/.test(requests[1].url), requests[1] && requests[1].url);

  requests.length = 0;
  sandbox.confirm = () => false;     // 用户点了「取消」
  await A().launchTool('ehole');
  await sleep(20);
  check('用户拒绝时不再重试（只 1 次请求）', requests.length === 1, requests.length);

  requests.length = 0;
  handler = () => ({ ok: true, json: async () => ({ ok: true, message: '已启动 Y' }) });
  await A().launchTool('httpx');
  await sleep(20);
  check('低危工具直接启动，不多确认一次', requests.length === 1, requests.length);

  console.log('\n' + '='.repeat(56));
  console.log(`  通过 ${ok.length} 项，失败 ${fail.length} 项`);
  for (const n of fail) console.log(`    FAIL: ${n}`);
  console.log('='.repeat(56));
  process.exit(fail.length ? 1 : 0);
})();
