/* 合规红线与模板（P1 占位，P2 实现）。 */
import { placeholder } from '/console-assets/views/_placeholder.js?v=0502';

export const render = placeholder({
  title: '合规与模板',
  goal: '把合规红线、调用模板、报告模板、以及 FOFA/CEye 密钥做成可编辑界面。',
  items: [
    '红线 Markdown 按 <code>##</code> 分节编辑（低危，直接写 + 留痕）',
    '调用模板表格 CRUD',
    'FOFA / CEye 密钥表单（<strong>读取时打码</strong>，只回显 has_key）',
    '顺带闭合已知问题：FOFA 未配置时仍出现在模型工具清单里',
  ],
  apis: [['GET', '/api/console/rules', 'todo'], ['POST', '/api/console/rules/commit', 'todo'],
         ['GET', '/api/console/templates', 'todo'], ['POST', '/api/console/secrets', 'todo']],
  files: [['data/rules/compliance-redlines.md', '8.7 KB 合规红线'],
          ['data/invocation_templates.json', '4 KB 调用模板'],
          ['config.yaml', 'FOFA/CEye 密钥（扁平格式，改键名会导致读不到）']],
});

// 改 config.yaml 的注意点：它**不被 config.py 读取**，只被 app/fofa.py 用自写的
// 扁平解析器读（不保证有 pyyaml）。所以必须保持 `key: value` 扁平格式与既有键名，
// 否则又是一次「改了没生效」。
