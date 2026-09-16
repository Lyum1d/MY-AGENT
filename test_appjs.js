/* 用最小 DOM 桩执行 app.js，锁定两条容易回归的行为：
 *  1) 面板加载失败必须「说出来」——网络层失败不刷屏，HTTP 层失败（404/500）要提示；
 *     这条是为了防止「新接口在旧后端上 404 → 面板静默空着 → 用户以为功能坏了」重演。
 *  2) 后端连不上时状态栏要给出提示并自动重试，而不是永久卡在「未连接」。
 *
 * 运行：node test_appjs.js
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const WEB = path.join('C:', 'Users', 'wang', 'Desktop', 'src-agent', 'web');
// 和 index.html 一样：先 graph.js 再 app.js（app.js 的 init 里要用 GraphView）
const SRC = fs.readFileSync(path.join(WEB, 'graph.js'), 'utf8')
  + '\n' + fs.readFileSync(path.join(WEB, 'app.js'), 'utf8');

const ok = [], fail = [];
const fetched = [];            // 记录发起过的请求 URL
const check = (n, c, e = '') => {
  (c ? ok : fail).push(n);
  console.log(`  [${c ? 'PASS' : 'FAIL'}] ${n}${e !== '' ? ' -> ' + e : ''}`);
};

/* ---------- 记录型伪 DOM ---------- */
const appended = [];      // #messages 里追加的文本
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
    getComputedTextLength: () => 60,      // graph.js 的 fitText 要用它量宽度
  };
  return el;
}
const messagesEl = makeEl();
messagesEl.appendChild = function (child) {
  this.children.push(child);
  appended.push(child.textContent || '');
  return child;
};
const statusEl = makeEl();

const els = {};                 // 按 id 缓存，便于回读被写入的内容
function byId(id) {
  if (id === 'messages') return messagesEl;
  if (id === 'status') return statusEl;
  return els[id] || (els[id] = makeEl());
}
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
  // 后端默认「连不上」：模拟服务未启动 / 正在重启（顺便记录请求，便于断言调用次数）
  fetch: (u) => { fetched.push(String(u)); return Promise.reject(new TypeError('Failed to fetch')); },
  localStorage: { getItem: () => '', setItem() {}, removeItem() {} },
  location: { href: '/', reload() {} },
  navigator: {},
  alert() {},
  confirm: () => false,
};
sandbox.window = sandbox;
sandbox.addEventListener = () => {};
sandbox.globalThis = sandbox;
const timers = [];
sandbox.setTimeout = (fn, ms) => { timers.push({ fn, ms }); return timers.length; };
sandbox.clearTimeout = () => {};
sandbox.requestAnimationFrame = (fn) => fn();
vm.createContext(sandbox);
process.on('unhandledRejection', () => {});

/* ------------------------------------------------------------------
 * 下线自检（2026-09-16）
 *
 * 本脚本守的是**本地自研前端**：线索树导航（renderThreadNav）、线索图 UI
 * （GraphView / deriveCausal）、面板加载失败提示（warnLoad）、线索高度记忆
 * （treeHeightLimit / pendingRestoreSid）。
 *
 * 拉上游更新（Lyum1d/MY-AGENT）时 update.py 把 web/{app.js,index.html} 整体覆盖，
 * 上游版里没有这些函数 —— 前端入口已下线。此处**不删脚本**（将来恢复前端时
 * 它还是现成的验收标准），改为显式报告并退出，避免以 ReferenceError 崩掉
 * （那种死法在回归报告里只显示「没有解析到结果统计」，很容易被忽略）。
 * ------------------------------------------------------------------ */
const REQUIRED = ['warnLoad', 'refreshStatus', 'renderThreadNav', 'GraphView', 'deriveCausal'];
const missing = REQUIRED.filter(fn => !new RegExp('(function|const|let|var)\\s+' + fn + '\\b').test(SRC));
if (missing.length) {
  console.log('  [跳过] 前端主流程：依赖的本地自研前端函数已下线 -> ' + missing.join(', '));
  console.log('         原因：v006 上游 web/app.js 里不存在这些函数（线索树导航 / 线索图 UI /');
  console.log('               面板加载失败提示），属拉上游更新时被整体覆盖。');
  console.log('         说明：脚本保留，恢复前端后可直接重新启用；后端线索图链路仍由');
  console.log('               test_graph.py 与 test_graph_e2e.py 覆盖。');
  console.log('\n========================================================');
  console.log('  通过 0 项，失败 0 项（已下线，未执行）');
  console.log('========================================================');
  process.exit(0);
}

vm.runInContext(
  SRC + '\n;globalThis.__api = { warnLoad, refreshStatus, renderThreadNav, '
      + 'currentThreadTitle, applyTreeHeight, treeHeightLimit, '
      + 'pendingRestoreSid, restoreLastThread, persistThread, loadTree, state, '
      + 'GraphView, loadFindings, loadFacts, deriveCausal, '
      + 'setGraphView: (v) => { graphView = v; } };',
  sandbox, { filename: 'app.js' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

(async () => {
  await sleep(150);        // 让 init() 里那串异步加载跑起来
  const base = appended.length;

  console.log('=== 一、加载失败要说出来 ===');
  check('app.js 里定义了 warnLoad', typeof sandbox.__api.warnLoad === 'function');

  sandbox.__api.warnLoad('模型列表', new Error('Failed to fetch'));
  check('网络层失败不刷屏（交给顶栏状态统一报）', appended.length === base,
    `追加了 ${appended.length - base} 条`);

  sandbox.__api.warnLoad('漏洞发现', new Error('404 Not Found'));
  const added = appended.slice(base);
  check('HTTP 层失败会提示', added.length === 1, added.join(' | '));
  check('提示里带面板名与原因',
    added.length === 1 && /漏洞发现/.test(added[0]) && /404/.test(added[0])
      && /加载失败/.test(added[0]), added[0] || '(无)');

  sandbox.__api.warnLoad('已证事实', new Error('500 Internal Server Error'));
  check('500 也会提示', appended.length === base + 2,
    appended.slice(base + 1).join(' | '));

  let threw = false;
  try {
    sandbox.__api.warnLoad('异常情况', undefined);
    sandbox.__api.warnLoad('异常情况', null);
  } catch (e) { threw = true; }
  check('传入 undefined/null 不会抛异常', !threw);

  console.log('\n=== 二、连不上后端时的自动重试 ===');
  check('状态栏已写出未连接提示', /后端未连接/.test(statusEl.innerHTML),
    statusEl.innerHTML.slice(0, 80));
  check('提示里说明了原因与正在重试',
    /Failed to fetch/.test(statusEl.innerHTML) && /重试/.test(statusEl.innerHTML));
  check('已排定重试定时器', timers.length > 0,
    timers.length ? `${timers[timers.length - 1].ms}ms` : '无');

  console.log('\n=== 三、线索导航（回不去旧对话的兜底入口）===');
  const { renderThreadNav, state } = sandbox.__api;
  const nav = byId('threadNav');

  state.sessionId = null;
  state.graph = null;
  renderThreadNav();
  check('没有选中线索时导航为空', nav.innerHTML === '', nav.innerHTML || '(空)');

  // 主线索：无父节点
  state.sessionId = 't_root';
  state.graph = { nodes: [
    { id: 'project:p', node_type: 'Project', title: '项目' },
    { id: 't_root', node_type: 'Thread', title: '主线索', data: { parent: '' } },
  ], edges: [] };
  renderThreadNav();
  check('主线索显示 🏠 且只标当前位置',
    /🏠/.test(nav.innerHTML) && /tn-here/.test(nav.innerHTML)
      && !/tn-back/.test(nav.innerHTML), nav.innerHTML);

  // 分支：父线索应是可点击的返回入口
  state.sessionId = 't_child';
  state.graph = { nodes: [
    { id: 'project:p', node_type: 'Project', title: '项目' },
    { id: 't_root', node_type: 'Thread', title: '主线索', data: { parent: '' } },
    { id: 't_child', node_type: 'Thread', title: '分支线索', data: { parent: 't_root' } },
  ], edges: [] };
  renderThreadNav();
  check('分支显示 🧭 并列出上级', /🧭/.test(nav.innerHTML), nav.innerHTML);
  check('上级线索渲染成可点按钮且调用 openThread',
    /class="tn-back"/.test(nav.innerHTML) && /openThread\('t_root'\)/.test(nav.innerHTML),
    nav.innerHTML);
  check('当前线索标为 tn-here 且不可点',
    /tn-here[^>]*>分支线索/.test(nav.innerHTML)
      && !/openThread\('t_child'\)/.test(nav.innerHTML), nav.innerHTML);
  check('导航里含上级标题文字', /主线索/.test(nav.innerHTML));

  // 三层：爷爷也应该在链上
  state.sessionId = 't_grand';
  state.graph.nodes.push(
    { id: 't_grand', node_type: 'Thread', title: '孙线索', data: { parent: 't_child' } });
  renderThreadNav();
  check('多级分支能列出整条路径',
    /openThread\('t_root'\)/.test(nav.innerHTML)
      && /openThread\('t_child'\)/.test(nav.innerHTML)
      && /孙线索/.test(nav.innerHTML), nav.innerHTML);

  // 超长标题要截断，避免把头部挤爆
  state.graph.nodes.push(
    { id: 't_long', node_type: 'Thread',
      title: '一个非常非常长的线索名称用于测试截断', data: { parent: 't_root' } });
  state.sessionId = 't_long';
  renderThreadNav();
  check('超长线索名被截断', /…/.test(nav.innerHTML), nav.innerHTML.slice(0, 120));

  console.log('\n=== 四、线索图高度按视口夹取 ===');
  // 桩里视口高度固定 800
  check('高度上限受视口约束（小窗口不会把聊天区挤没）',
    sandbox.__api.treeHeightLimit() === Math.round(800 * 0.62),
    'limit=' + sandbox.__api.treeHeightLimit());

  sandbox.localStorage.getItem = () => '700';      // 假装之前在小窗口存过很高的值
  sandbox.__api.applyTreeHeight();
  const h = parseInt(byId('treeCanvas').style.height, 10);
  check('读取到的过高值会被夹到上限内', h === sandbox.__api.treeHeightLimit(), h);

  sandbox.localStorage.getItem = () => '40';       // 过小则抬到下限
  sandbox.__api.applyTreeHeight();
  check('过小的高度会被抬到下限', parseInt(byId('treeCanvas').style.height, 10) === 160,
    byId('treeCanvas').style.height);

  console.log('\n=== 五、刷新后回到上次的线索 ===');
  const api = sandbox.__api;
  const store = {};
  sandbox.localStorage.getItem = (k) => (k in store ? store[k] : null);
  sandbox.localStorage.setItem = (k, v) => { store[k] = String(v); };

  state.sessionId = null;
  state.graph = { nodes: [
    { id: 'project:p', node_type: 'Project' },
    { id: 't_root', node_type: 'Thread', title: '主线索' },
  ], edges: [] };

  check('没记过线索时不恢复', api.pendingRestoreSid() === '', api.pendingRestoreSid());

  api.persistThread('t_root');
  check('记住后能取出来', api.pendingRestoreSid() === 't_root', api.pendingRestoreSid());

  api.persistThread('别的项目的线索');
  check('记的是别的项目的线索则不恢复（防跨项目乱跳）',
    api.pendingRestoreSid() === '', api.pendingRestoreSid());

  api.persistThread('');
  check('主动清空后不恢复', api.pendingRestoreSid() === '');

  // 只恢复一次：第二次调用不应再发请求
  api.persistThread('t_root');
  const n0 = fetched.length;
  const r1 = await api.restoreLastThread();
  const n1 = fetched.length;
  check('首次会去恢复（发出了请求）', n1 > n0, `请求 +${n1 - n0}`);
  check('恢复失败时如实返回 false（后端连不上）', r1 === false, String(r1));
  const r2 = await api.restoreLastThread();
  check('第二次调用不再重复恢复', fetched.length === n1 && r2 === false,
    `请求 +${fetched.length - n1}`);

  console.log('\n=== 六、快速切换视图的响应竞态 ===');
  // 造一个可控的 fetch：请求先挂起，由测试决定谁先返回
  const pending = [];
  const jsonResp = (o) => ({ ok: true, status: 200, statusText: 'OK',
    json: () => Promise.resolve(o) });
  sandbox.fetch = (u, o) => new Promise((res, rej) => {
    pending.push({ url: String(u), opts: o || {}, res, rej });
  });
  state.currentProject = 'proj1';

  api.setGraphView('attack');
  const t1 = api.loadTree();                       // 第 1 个请求：攻击图
  api.setGraphView('causal');
  const t2 = api.loadTree();                       // 第 2 个请求：因果图
  await sleep(30);
  const graphReqs = pending.filter(p => p.url.includes('/graph/'));
  check('两次切换各发一个请求', graphReqs.length === 2,
    graphReqs.map(p => p.url.split('/').pop()).join(','));

  // 故意让「先发的」后返回：这正是会覆盖界面的那种顺序
  const causalReq = graphReqs.find(p => p.url.includes('causal'));
  const attackReq = graphReqs.find(p => p.url.includes('attack'));
  causalReq.res(jsonResp({ nodes: [{ id: 'causal-node', node_type: 'Evidence' }], edges: [] }));
  await t2;
  attackReq.res(jsonResp({ nodes: [{ id: 'attack-node', node_type: 'Thread' }], edges: [] }));
  await t1;

  check('过期响应被丢弃，不会覆盖新视图的数据',
    state.graph && state.graph.nodes[0] && state.graph.nodes[0].id === 'causal-node',
    state.graph && state.graph.nodes[0] && state.graph.nodes[0].id);

  // 渲染抛错时：数据必须保留，错误也必须如实说是「渲染失败」而不是「加载失败」
  api.setGraphView('attack');
  const mark3 = pending.length;                 // 只看这之后新入队的请求
  const t3 = api.loadTree();
  await sleep(30);
  const req3 = pending.slice(mark3).find(p => p.url.includes('/graph/attack'));
  check('第三次请求已发出', !!req3, '新增 ' + (pending.length - mark3));
  const realRender = api.GraphView.render;
  api.GraphView.render = () => { throw new Error('boom-渲染炸了'); };
  const loggedBefore = appended.length;
  req3.res(jsonResp({ nodes: [{ id: 'keep-me', node_type: 'Thread' }], edges: [] }));
  await t3;

  check('渲染抛错时数据不被抹掉（state.graph 保留）',
    state.graph && state.graph.nodes[0] && state.graph.nodes[0].id === 'keep-me',
    JSON.stringify(state.graph));
  const tail = appended.slice(loggedBefore).join(' | ');
  check('错误文案说的是「渲染失败」而不是「加载失败」',
    /线索图渲染失败/.test(tail) && !/线索图加载失败/.test(tail), tail);
  api.GraphView.render = realRender;

  // 同一类竞态：快速切项目时，旧项目的响应不能覆盖新项目的面板
  const mark4 = pending.length;
  state.currentProject = 'projA';
  const f1 = api.loadFindings();
  state.currentProject = 'projB';
  const f2 = api.loadFindings();
  await sleep(30);
  const reqs4 = pending.slice(mark4);
  check('两次切项目各发一个请求', reqs4.length === 2,
    reqs4.map(r => r.url.split('/').pop()).join(','));
  byId('findingList').innerHTML = '新项目的面板';
  // 让先发的（projA）后返回
  reqs4[1].res(jsonResp({ findings: [{ id: 'B', title: 'B项目漏洞', severity: '低危' }] }));
  await f2;
  const afterB = byId('findingList').innerHTML;
  reqs4[0].res(jsonResp({ findings: [{ id: 'A', title: 'A项目漏洞', severity: '高危' }] }));
  await f1;
  check('旧项目的过期响应不会覆盖新项目面板',
    byId('findingList').innerHTML === afterB && !/A项目漏洞/.test(byId('findingList').innerHTML),
    byId('findingList').innerHTML.slice(0, 60));

  console.log('\n=== 七、「⟳ 生成线索链」按钮 ===');
  const alerts = [];
  sandbox.alert = (m) => alerts.push(String(m));

  // 按钮只有 5 行代码，但它是因果图唯一的入口，之前从没被验过
  state.currentProject = 'projX';
  api.setGraphView('causal');
  const btn = byId('deriveBtn');
  const mark5 = pending.length;
  const d1 = api.deriveCausal();
  await sleep(30);
  const req5 = pending.slice(mark5)[0];
  check('点了按钮会请求因果图派生接口',
    !!req5 && req5.url.endsWith('/graph/causal/derive'), req5 && req5.url);
  check('用 POST 调用（派生会重建数据）', !!req5 && req5.opts.method === 'POST',
    req5 && req5.opts.method);
  check('请求期间按钮置为「生成中…」且禁用',
    /生成中/.test(btn.textContent) && btn.disabled === true,
    `${btn.textContent} disabled=${btn.disabled}`);

  const loggedBefore5 = appended.length;
  req5.res(jsonResp({ nodes: [{ id: 'e1', node_type: 'Evidence' }], edges: [] }));
  await d1;
  check('成功后画布数据被替换为派生的因果图',
    state.graph && state.graph.nodes[0] && state.graph.nodes[0].id === 'e1',
    JSON.stringify(state.graph));
  check('成功后提示节点/关系数量',
    /线索链已生成：1 个节点、0 条关系/.test(appended.slice(loggedBefore5).join(' ')),
    appended.slice(loggedBefore5).join(' | '));
  check('无论成败按钮都要恢复（否则卡在"生成中"）',
    btn.disabled === false && btn.textContent === '⟳ 生成线索链',
    `${btn.textContent} disabled=${btn.disabled}`);

  // 失败路径
  const mark6 = pending.length;
  const d2 = api.deriveCausal();
  await sleep(30);
  const req6 = pending.slice(mark6)[0];
  req6.rej(new Error('500 Internal Server Error'));
  await d2;
  check('失败时弹窗告知原因', alerts.some(a => /生成失败/.test(a)), alerts.join(' | '));
  check('失败后按钮同样要恢复',
    btn.disabled === false && btn.textContent === '⟳ 生成线索链',
    `${btn.textContent} disabled=${btn.disabled}`);

  console.log('\n' + '='.repeat(52));
  console.log(`  通过 ${ok.length} 项，失败 ${fail.length} 项`);
  fail.forEach((f) => console.log(`    FAIL: ${f}`));
  console.log('='.repeat(52));
  process.exit(fail.length ? 1 : 0);
})();
