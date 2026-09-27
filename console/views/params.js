/* 运行参数与闸门（P1 占位，P2 实现）。 */
import { placeholder } from '/console-assets/views/_placeholder.js?v=050';

export const render = placeholder({
  title: '运行参数',
  goal: '把 config.py 里 220 处调用点消费的运行参数与闸门开关做成可调表，'
      + '带不变量校验与生效回显。',
  items: [
    '分组：编排 / 超时 / 预算 / 闸门开关 / 分档',
    '每项显示「当前值 · 默认值 · 来源（env 还是覆盖文件）」',
    '提交前跑不变量校验（复用既有 <code>config.timeout_warnings()</code>，不另写一套）',
    '<strong>热生效</strong>：全项目 0 处 <code>from .config import X</code>、'
      + '220 处 <code>config.X</code> 属性访问，因此运行时 <code>setattr</code> 立即对所有调用点生效，不用重启',
  ],
  apis: [['GET', '/api/console/params', 'todo'], ['POST', '/api/console/params/preview', 'todo'],
         ['POST', '/api/console/params/commit', 'todo'], ['POST', '/api/console/params/reset', 'todo']],
  files: [['app/config.py', '导入期常量（env 优先）'],
          ['data/runtime_overrides.json', '控制台写入的覆盖值（待建）']],
});

// 不变量（提交前必须校验，否则会造出「配了两个上限但只有一个生效」这类静默错误）：
//   TOOL_IDLE_TIMEOUT < TOOL_TIMEOUT
//   PY_EXEC_TIMEOUT >= TOOL_IDLE_TIMEOUT
//   PY_EXEC_GRADE_LEVEL_* 必须是合法风险等级
//   FAILURE_SWITCH_THRESHOLD < FAILURE_STOP_THRESHOLD
