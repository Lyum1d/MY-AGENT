/* 配置控制台前端回归（v050 P1）。
 *
 * ## 这一版测什么、不测什么（诚实划线）
 *
 * **测**：`console/lib.js` 里的**纯函数**——真实 import 进来跑，断言行为。
 * 这些函数错了会**静默**出问题（差异视图颜色反了 → 把「新增授权」看成「移除授权」；
 * 端口解析错了 → 悄悄改变授权范围），所以必须测。
 *
 * **只做结构断言**：DOM 相关部分（登录闸门、视图路由、弹窗）本版只做静态检查
 * （关键调用是否存在），**没有**跑真实 DOM。这是 P1 的已知缺口 ——
 * 现有 `web/app.js` 的测试（test_appjs.js）靠手写假 DOM 桩，脆弱难维护；
 * 本控制台选择先把纯逻辑抽出来测，DOM 行为测试留到 P2/P3 用更靠谱的方式补。
 *
 * 运行：node test_console_js.js
 */
const fs = require('fs');
const path = require('path');
// Windows 下动态 import 绝对路径必须转成 file:// URL，否则报
// ERR_UNSUPPORTED_ESM_URL_SCHEME（Received protocol 'c:'）。
const { pathToFileURL } = require('url');

const WEB = path.join(__dirname, 'console');   // 相对脚本定位，不写死他人机器路径
const ok = [], fail = [];

const check = (n, c, e = '') => {
  (c ? ok : fail).push(n);
  console.log(`  [${c ? 'PASS' : 'FAIL'}] ${n}${e !== '' ? ' → ' + e : ''}`);
};
const read = (p) => fs.readFileSync(path.join(WEB, p), 'utf8');

(async () => {
  const lib = await import(pathToFileURL(path.join(WEB, 'lib.js')).href);

  /* ============ A. 纯函数行为 ============ */
  console.log('== A. 纯函数（esc / diffHtml / parseList / fmtTime / alertBox） ==');

  check('esc 转义 & < > " 单引号',
    lib.esc('<a href="x">&\'y\'</a>') === '&lt;a href=&quot;x&quot;&gt;&amp;&#39;y&#39;&lt;/a&gt;',
    lib.esc('<a href="x">&\'y\'</a>'));
  check('esc 把 null / undefined 变成空串（不产生 "null" 字样）',
    lib.esc(null) === '' && lib.esc(undefined) === '');
  check('esc 对数字正常', lib.esc(0) === '0' && lib.esc(443) === '443');

  const d1 = lib.diffHtml(['added.test'], ['removed.test'], 3);
  check('diffHtml：被移除的项用 del（红）类',
    /class="row del">− removed\.test</.test(d1), d1);
  check('diffHtml：新增的项用 add（绿）类',
    /class="row add">\+ added\.test</.test(d1), d1);
  check('diffHtml：颜色语义不能反（del 里不含新增项、add 里不含移除项）',
    !/class="row del">− added/.test(d1) && !/class="row add">\+ removed/.test(d1));
  check('diffHtml：显示保留条数', /保留 3 条不变/.test(d1), d1);

  const d2 = lib.diffHtml([], [], 0);
  check('diffHtml：无变化时给出「无变化」提示（空白会被误读成加载失败）',
    /无变化/.test(d2), d2);

  const d3 = lib.diffHtml(['<img src=x onerror=alert(1)>'], []);
  check('diffHtml：主机名被转义（不产生可执行标签）',
    !/<img/.test(d3) && /&lt;img/.test(d3), d3);

  check('parseList：空串 → null（= 不限，与后端语义一致）', lib.parseList('') === null);
  check('parseList：undefined → null', lib.parseList(undefined) === null);
  check('parseList：只有空白 → null', lib.parseList('   ') === null);
  // 默认返回**字符串**（协议名就是字符串），要数字得显式 numeric:true ——
  // 这是有意的契约：同一个函数服务 ports 与 schemes 两种字段。
  check('parseList：默认返回字符串（逗号分隔）',
    JSON.stringify(lib.parseList('80,443')) === '["80","443"]',
    JSON.stringify(lib.parseList('80,443')));
  check('parseList：默认返回字符串（空白分隔）',
    JSON.stringify(lib.parseList('80 443')) === '["80","443"]');
  check('parseList：混合分隔 + 保持原序',
    JSON.stringify(lib.parseList('80, 443  8080')) === '["80","443","8080"]');
  check('parseList：协议名原样保留（大小写不在这里改，交给后端校验）',
    JSON.stringify(lib.parseList('HTTPS,http')) === '["HTTPS","http"]');
  check('parseList(numeric)：转成数字',
    JSON.stringify(lib.parseList('80,443', { numeric: true })) === '[80,443]');
  check('parseList(numeric)：非数字被滤掉',
    JSON.stringify(lib.parseList('80,abc', { numeric: true })) === '[80]');
  check('parseList(numeric)：全非数字 → null（不会提交 [NaN]）',
    lib.parseList('abc', { numeric: true }) === null);
  check('parseList(numeric)：不会产生 NaN',
    !JSON.stringify(lib.parseList('80,x', { numeric: true })).includes('null'));

  check('fmtTime：0 → 占位符（不显示 1970）', lib.fmtTime(0) === '-');
  check('fmtTime：null → 占位符', lib.fmtTime(null) === '-');
  check('fmtTime：正常时间戳格式为 YYYY-MM-DD HH:MM',
    /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}$/.test(lib.fmtTime(1780000000)),
    lib.fmtTime(1780000000));

  check('alertBox：class 带等级',
    /class="alert high"/.test(lib.alertBox('high', 'x')));
  check('alertBox：文本被转义',
    !/<b>/.test(lib.alertBox('low', '<b>x</b>')));
  check('alertBox：未知等级不崩且有兜底图标',
    /class="alert weird"/.test(lib.alertBox('weird', 'x')));

  /* ============ B. 结构断言（DOM 部分，P1 已知缺口） ============ */
  console.log('\n== B. 接线结构断言（DOM 行为未覆盖，见文件头说明） ==');
  const core = read('core.js');
  const scope = read('views/scope.js');
  const html = read('index.html');

  check('core.js 请求带同源 Cookie（口令票据靠它）',
    /credentials:\s*'same-origin'/.test(core));
  check('core.js 在 401 时回到登录（登录过期要能自愈）',
    /res\.status\s*===\s*401/.test(core) && /showLogin\(/.test(core));
  check('core.js 面板加载失败会显示错误（不是静默空着）',
    /该面板加载失败/.test(core));
  check('core.js 不引 CDN / 绝对外链',
    !/https?:\/\//.test(core), (core.match(/https?:\/\/\S+/) || [''])[0]);
  check('core.js 八个视图都注册了',
    ['overview', 'scope', 'tools', 'params', 'rules', 'monitor', 'charts', 'audit']
      .every((v) => new RegExp(v + '\\s*:').test(core)));
  check('core.js 主题与作战界面共用同一个 localStorage 键',
    /src_theme/.test(core));

  check('index.html 二次确认勾选框存在且默认未勾',
    /id="modalAck"/.test(html) && !/id="modalAck"[^>]*checked/.test(html));
  check('index.html 说明「不放宽任何执行能力」',
    /不放宽任何执行能力/.test(html));
  check('index.html 说明未设口令时拒绝访问',
    /未设置时本控制台一律拒绝访问/.test(html));

  check('scope.js 提交必须带一次性确认票据',
    /confirm_token/.test(scope));
  check('scope.js 提交必须带文件哈希做乐观锁',
    /expect_sha256/.test(scope));
  check('scope.js 高危改动要求勾选确认（ack 文案在）',
    /已获得书面授权/.test(scope));
  check('scope.js 不提供「不含子域」开关（避免假承诺）',
    /本版<strong>不提供<\/strong>/.test(scope) && /假承诺/.test(scope));
  check('scope.js 的 include_subdomains 写死为 true',
    /include_subdomains:\s*true/.test(scope));
  check('scope.js 用 lib.parseList 解析端口/协议（可测的那份实现）',
    /parseList\(/.test(scope));

  const files = ['views/overview.js', 'views/scope.js', 'views/audit.js',
                 'views/tools.js', 'views/params.js', 'views/rules.js',
                 'views/monitor.js', 'views/charts.js', 'views/_placeholder.js'];
  check('全部视图文件存在', files.every((f) => fs.existsSync(path.join(WEB, f))));
  check('package.json 只声明模块类型、无任何依赖',
    (() => {
      const p = JSON.parse(read('package.json'));
      return p.type === 'module' && !p.dependencies && !p.devDependencies;
    })());

  console.log('\n' + '='.repeat(60));
  console.log(`结果：${ok.length} 通过 / ${fail.length} 失败`);
  if (fail.length) console.log('失败项：' + fail.join('、'));
  console.log('='.repeat(60));
  process.exit(fail.length ? 1 : 0);
})();
