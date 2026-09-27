/* 工具与分级（P1 占位，P2 实现）。 */
import { placeholder } from '/console-assets/views/_placeholder.js?v=050';

export const render = placeholder({
  title: '工具与分级',
  goal: '把 211 个工具的分级、禁用、旗标白名单、能力标签（caps）、target_type '
      + '做成可查可改的表格，替掉手改两个 JSON。',
  items: [
    '按分级 / 分类 / 可用性 / 是否进模型清单筛选',
    '行内改分级（L0~L3）、禁用（必须填理由）、改旗标白名单与 caps',
    '改完自动重载 registry，并<strong>回显重载前后差异</strong>——防「改了没生效」',
    '展示「交互式已剔除」与「文件缺失」两类特殊工具',
  ],
  apis: [['GET', '/api/console/tools', 'todo'], ['POST', '/api/console/tools/preview', 'todo'],
         ['POST', '/api/console/tools/commit', 'todo'], ['POST', '/api/console/tools/reload', 'todo'],
         ['GET', '/api/tools', 'ready']],
  files: [['data/risk_grades.json', '11 KB 风险分级'], ['data/tool_overrides.json', '15 KB 工具覆写']],
});

// 注意：改这两个文件后**必须让 registry 重载**（它有缓存）。
// 只改文件不重载 = 服务继续用旧分级，而操作者以为已生效 —— 本项目反复踩过这一类。
