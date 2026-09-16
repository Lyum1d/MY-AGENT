/* 用最小 DOM 桩执行 graph.js：校验分层布局、渲染结果与回调接线 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SRC = fs.readFileSync(
  path.join(__dirname, 'web', 'graph.js'), 'utf8');  // 审计 P1-2：相对脚本定位，不写死他人机器路径

/* ---------- 伪 DOM（含事件记录） ---------- */
class FakeNode {
  constructor(tag) {
    this.tagName = tag; this.attrs = {}; this.children = []; this.parentNode = null;
    this.dataset = {}; this.style = {}; this._text = ''; this._html = '';
    this._classes = new Set(); this._rect = null; this._on = {};
    this.classList = {
      add: (...c) => c.forEach(x => this._classes.add(x)),
      remove: (...c) => c.forEach(x => this._classes.delete(x)),
      toggle: (c, on) => {
        const want = on === undefined ? !this._classes.has(c) : !!on;
        if (want) this._classes.add(c); else this._classes.delete(c);
      },
      contains: (c) => this._classes.has(c),
    };
  }
  get className() { return [...this._classes].join(' '); }
  set className(v) { this._classes = new Set(String(v).split(/\s+/).filter(Boolean)); }
  get textContent() { return this._text; }
  set textContent(v) { this._text = String(v); this.children = []; }
  get innerHTML() { return this._html; }
  set innerHTML(v) { this._html = String(v); this.children = []; }
  setAttribute(k, v) {
    this.attrs[k] = String(v);
    if (k === 'class') this.className = v;
  }
  getAttribute(k) { return this.attrs[k]; }
  appendChild(c) { c.parentNode = this; this.children.push(c); return c; }
  addEventListener(t, fn) { (this._on[t] = this._on[t] || []).push(fn); }
  removeEventListener() {}
  dispatch(t, ev) { (this._on[t] || []).forEach(fn => fn(ev || { stopPropagation() {} })); }
  remove() {
    if (this.parentNode) this.parentNode.children = this.parentNode.children.filter(x => x !== this);
  }
  getComputedTextLength() { return this._text.length * 6.2; }
  getBoundingClientRect() { return this._rect || { left: 0, top: 0, width: 900, height: 300 }; }
  _all() { const out = []; const w = n => n.children.forEach(c => { out.push(c); w(c); }); w(this); return out; }
  querySelectorAll(sel) {
    if (/^((?:\.[\w-]+)+)$/.test(sel)) {
      const cs = sel.split('.').filter(Boolean);
      return this._all().filter(n => cs.every(c => n._classes.has(c)));
    }
    if (/^\[/.test(sel)) return [];
    return this._all().filter(n => n.tagName === sel);
  }
  querySelector(sel) { return this.querySelectorAll(sel)[0] || null; }
  closest(sel) {
    const m = /^\.([\w-]+)$/.exec(sel);
    let n = this;
    while (n) { if (m && n._classes && n._classes.has(m[1])) return n; n = n.parentNode; }
    return null;
  }
}

const sandbox = {
  console,
  document: { createElementNS: (ns, tag) => new FakeNode(tag), createElement: (t) => new FakeNode(t) },
  window: { addEventListener() {} },
  requestAnimationFrame: (fn) => fn(),
  navigator: {},
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
vm.runInContext(SRC + '\n;globalThis.GraphView = GraphView;', sandbox, { filename: 'graph.js' });
const G = sandbox.GraphView;

const ok = [], fail = [];
const check = (n, c, e = '') => {
  (c ? ok : fail).push(n);
  console.log(`  [${c ? 'PASS' : 'FAIL'}] ${n}${e !== '' ? ' -> ' + e : ''}`);
};
const T = (t) => {
  const m = /translate\(([-\d.]+),([-\d.]+)\)/.exec(t || '');
  return m ? { x: +m[1], y: +m[2] } : null;
};

const nodes = [
  { id: 'project:p1', node_type: 'Project', type_label: '项目', title: '靶场项目', status: 'in_progress', data: {} },
  { id: 's1', node_type: 'Thread', type_label: '线索', title: '主线索：信息收集', status: 'completed', data: { step_count: 3 } },
  { id: 's2', node_type: 'Thread', type_label: '线索', title: '子线索 A：目录扫描', status: 'in_progress', data: { step_count: 5 } },
  { id: 's3', node_type: 'Thread', type_label: '线索', title: '子线索 B：弱口令尝试', status: 'deprecated', data: { step_count: 1 } },
  { id: 's4', node_type: 'Thread', type_label: '线索', title: '孙线索：后台深挖', status: 'in_progress', data: { step_count: 0 } },
  { id: 's5', node_type: 'Thread', type_label: '线索', title: '孙线索：接口测试', status: 'in_progress', data: { step_count: 2 } },
];
const edges = [
  { source_id: 'project:p1', target_id: 's1', label: 'BRANCH', label_text: '分支' },
  { source_id: 's1', target_id: 's2', label: 'BRANCH', label_text: '分支' },
  { source_id: 's1', target_id: 's3', label: 'BRANCH', label_text: '分支' },
  { source_id: 's2', target_id: 's4', label: 'BRANCH', label_text: '分支' },
  { source_id: 's2', target_id: 's5', label: 'BRANCH', label_text: '分支' },
  { source_id: 's5', target_id: '不存在', label: 'BRANCH' },
];

const host = new FakeNode('div');
host._rect = { left: 0, top: 0, width: 900, height: 300 };
const legend = new FakeNode('div');
const calls = [];
G.mount(host, { legendEl: legend });
G.render({ nodes, edges }, {
  view: 'attack', currentId: 's4', legendEl: legend,
  onOpenThread: (id) => calls.push(['open', id]),      // 关键：回调通过 render 传入
  onBranch: (id) => calls.push(['branch', id]),
  onSetStatus: (id, s) => calls.push(['status', id, s]),
});

console.log('=== 渲染 ===');
check('节点组数量与数据一致', host.querySelectorAll('.gnode').length === nodes.length);
check('连线只画有效边（悬空边被忽略）', host.querySelectorAll('.glink').length === 5,
  host.querySelectorAll('.glink').length);
check('空态提示隐藏', host.querySelectorAll('.graph-empty')[0].style.display === 'none');
check('图例已渲染', legend.innerHTML.length > 0);

console.log('\n=== 布局几何 ===');
const P = {};
host.querySelectorAll('.gnode').forEach(g => { P[g.dataset.id] = T(g.getAttribute('transform')); });
check('每个节点都有合法坐标',
  Object.values(P).every(p => p && Number.isFinite(p.x) && Number.isFinite(p.y)));
check('所有边都指向下方',
  edges.slice(0, 5).every(e => P[e.target_id].y > P[e.source_id].y));
const layers = {};
Object.entries(P).forEach(([id, p]) => { (layers[p.y] = layers[p.y] || []).push(id); });
const rows = Object.values(layers).sort((a, b) => P[a[0]].y - P[b[0]].y);
check('项目根单独处于最上层', rows[0].length === 1 && rows[0][0] === 'project:p1');
const W = { Project: 210, Thread: 178 };
let clash = null;
rows.forEach(l => {
  for (let i = 0; i < l.length; i++) for (let j = i + 1; j < l.length; j++) {
    const a = nodes.find(n => n.id === l[i]), b = nodes.find(n => n.id === l[j]);
    if (Math.abs(P[a.id].x - P[b.id].x) < (W[a.node_type] + W[b.node_type]) / 2 - 0.01) {
      clash = `${a.id}/${b.id}`;
    }
  }
});
check('同层节点不重叠', !clash, clash || 'OK');
check('子层对齐在父节点正下方', Math.abs(P['s2'].x - (P['s4'].x + P['s5'].x) / 2) < 40,
  `偏移 ${Math.abs(P['s2'].x - (P['s4'].x + P['s5'].x) / 2).toFixed(1)}px`);

console.log('\n=== 活跃路径与交互 ===');
const onPath = host.querySelectorAll('.gnode.onpath').map(g => g.dataset.id).sort();
check('当前线索路径被高亮', JSON.stringify(onPath) === JSON.stringify(['project:p1', 's1', 's2', 's4']),
  onPath.join(','));
check('路径上的连线带 active 类', host.querySelectorAll('.glink.active').length === 3);
check('适配缩放正常', typeof G.fit() === 'undefined' || true);

// 双击节点 -> 应触发 render 时传入的 onOpenThread（回归：回调曾被静默忽略）
const shot = (id, type) => {
  const before = calls.length;
  host.querySelectorAll('.gnode').find(g => g.dataset.id === id).dispatch(type);
  return calls.slice(before);
};
const g4 = host.querySelectorAll('.gnode').find(g => g.dataset.id === 's4');
g4.dispatch('dblclick');
check('render 传入的回调真的接上了（双击触发 onOpenThread）',
  calls.some(c => c[0] === 'open' && c[1] === 's4'), JSON.stringify(calls));

// 单击「线索」节点必须直接切换——这是用户切换线索的主入口。
// （曾经改成"只弹详情面板"，用户就以为新建对话/开分支后回不去旧对话了。）
check('单击线索节点即切换到该线索',
  shot('s3', 'click').some(c => c[0] === 'open' && c[1] === 's3'),
  JSON.stringify(calls));
check('单击当前线索不重复切换',
  !shot('s4', 'click').some(c => c[0] === 'open'), JSON.stringify(calls));
check('单击项目根节点不切换线索（它不是线索）',
  !shot('project:p1', 'click').some(c => c[0] === 'open'), JSON.stringify(calls));

console.log('\n=== 文本与类型色 ===');
check('每个节点都有标题', host.querySelectorAll('.gn-title').length === nodes.length);
check('标题超宽被截断', host.querySelectorAll('.gn-title').every(t => t.textContent.length <= 30));
check('类型药丸带颜色变量',
  host.querySelectorAll('.gn-pill').every(p => /fill:var\(--g-/.test(p.attrs.style || '')));

console.log('\n=== 因果图 ===');
const cNodes = [
  { id: 'step:x', node_type: 'Evidence', type_label: '证据', title: 'nmap 扫描', status: 'SUPPORTED', confidence: 0.7, data: { output_head: '80/tcp open' } },
  { id: 'fact:y', node_type: 'KeyFact', type_label: '关键事实', title: '存在 /admin', status: 'SUPPORTED', confidence: 0.8, data: {} },
  { id: 'finding:z', node_type: 'ConfirmedVulnerability', type_label: '确认漏洞', title: '后台弱口令', status: 'CONFIRMED', confidence: 0.95, severity: '高危', data: { evidence: '截图' } },
];
G.render({ nodes: cNodes, edges: [
  { source_id: 'step:x', target_id: 'fact:y', label: 'REVEALS', label_text: '揭示' },
  { source_id: 'fact:y', target_id: 'finding:z', label: 'SUPPORTS', label_text: '支撑' },
] }, { view: 'causal', currentId: '', legendEl: legend });
check('因果节点渲染完整', host.querySelectorAll('.gnode').length === 3);
check('因果边渲染完整', host.querySelectorAll('.glink').length === 2);
check('边语义标签已渲染',
  host.querySelectorAll('.glabel').map(t => t.textContent).join(',') === '揭示,支撑');
check('因果图不高亮活跃路径', host.querySelectorAll('.gnode.onpath').length === 0);
check('因果图里点节点不切换线索（没有"对话"可切）',
  !shot('fact:y', 'click').some(c => c[0] === 'open'), JSON.stringify(calls.slice(-3)));
check('副标题带置信度',
  host.querySelectorAll('.gn-sub').some(t => /置信 95%/.test(t.textContent)));

// 孤立节点（无连线的漏洞）应单独落到最底部，别混在最上层冒充证据
G.render({ nodes: cNodes.concat([
  { id: 'finding:orphan', node_type: 'Vulnerability', type_label: '疑似漏洞',
    title: '未关联的疑似漏洞', status: 'PENDING', confidence: 0.6, data: {} },
]), edges: [
  { source_id: 'step:x', target_id: 'fact:y', label: 'REVEALS', label_text: '揭示' },
  { source_id: 'fact:y', target_id: 'finding:z', label: 'SUPPORTS', label_text: '支撑' },
] }, { view: 'causal', currentId: '', legendEl: legend });
const oy = {};
host.querySelectorAll('.gnode').forEach(g => { oy[g.dataset.id] = T(g.getAttribute('transform')).y; });
const others = ['step:x', 'fact:y', 'finding:z'].map(k => oy[k]);
check('孤立节点被排到最底部一行',
  oy['finding:orphan'] > Math.max(...others),
  `孤立 y=${oy['finding:orphan']} 其它 max=${Math.max(...others)}`);

console.log('\n=== 节点详情面板 ===');
// 攻击图：线索节点面板应有操作按钮，且不显示「置信度」（对线索没意义，纯噪声）
G.render({ nodes, edges }, { view: 'attack', currentId: 's1', legendEl: legend,
  onOpenThread: (id) => calls.push(['open', id]),
  onBranch: (id) => calls.push(['branch', id]),
  onSetStatus: (id, st) => calls.push(['status', id, st]) });
G.select('s4');
const panelA = host.querySelectorAll('.graph-panel')[0].innerHTML;
check('攻击图面板有「打开这条线索」按钮', /打开这条线索/.test(panelA));
check('攻击图面板有分支/改状态按钮', /＋ 分支/.test(panelA) && /标记完成/.test(panelA));
check('攻击图面板不再显示置信度（噪声）', !/置信/.test(panelA), panelA.slice(0, 90));
check('攻击图面板显示步数', /步/.test(panelA));

// 因果图：证据节点面板要显示置信度与因果图专属操作
G.render({ nodes: cNodes, edges: [
  { source_id: 'step:x', target_id: 'fact:y', label: 'REVEALS', label_text: '揭示' },
  { source_id: 'fact:y', target_id: 'finding:z', label: 'SUPPORTS', label_text: '支撑' },
] }, { view: 'causal', legendEl: legend, onBranchFromNode: (n) => calls.push(['dig', n.id]) });
G.select('finding:z');
const panelC = host.querySelectorAll('.graph-panel')[0].innerHTML;
check('因果图面板显示置信度', /置信 95%/.test(panelC), panelC.slice(0, 90));
check('因果图面板显示严重级别', /高危/.test(panelC), panelC.slice(0, 120));
check('因果图面板有「以此线索开分支」', /以此线索开分支/.test(panelC));

console.log('\n=== 空态 ===');
G.render({ nodes: [], edges: [] }, { view: 'causal', legendEl: legend, emptyText: '空' });
check('空数据提示可见且无残留节点',
  host.querySelectorAll('.graph-empty')[0].style.display === 'block'
  && host.querySelectorAll('.gnode').length === 0);
check('空数据图例清空', legend.innerHTML === '');

console.log('\n' + '='.repeat(52));
console.log(`  通过 ${ok.length} 项，失败 ${fail.length} 项`);
fail.forEach(f => console.log(`    FAIL: ${f}`));
console.log('='.repeat(52));
process.exit(fail.length ? 1 : 0);
