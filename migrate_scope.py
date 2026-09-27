# -*- coding: utf-8 -*-
"""把 `data/scope.json` 迁移为结构化条目（v050 配置控制台 P1）。

用法：
    python migrate_scope.py            # 预演，只打印报告，**不写盘**
    python migrate_scope.py --apply    # 落盘（写前自动备份）

做什么：把「`domains` 数组 + `_说明` 自由文本」反解成结构化 `targets`
（host / 是否含子域 / 端口 / 协议 / 补天 cid / 授权主体 / 确认日期 / 限制条件）。
`domains` 保留并自动同步；`_说明` **原文保留**（人工可读的授权依据不动）。
反解不出的条目标 `needs_review`，**不猜**。

为什么不硬编码任何 域名→cid 映射：本脚本入库，而 `scope.json` 不入库（含真实授权靶标）。
表写进代码就等于把交战数据抄进公开仓库 —— v045/v046 两版都在治这个病。
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from app import config, config_io, scope_migrate       # noqa: E402


def main() -> int:
    apply = "--apply" in sys.argv
    raw = config_io.read_json(config.SCOPE_FILE, default=None)
    if raw is None:
        print(f"[FAIL] 读不到或解析失败：{config.SCOPE_FILE}")
        return 1
    if not isinstance(raw, dict):
        print("[FAIL] scope.json 顶层不是对象")
        return 1
    if isinstance(raw.get("targets"), list) and raw["targets"]:
        print(f"[提示] 已存在 {len(raw['targets'])} 条结构化条目，本次将补齐缺失字段"
              "（不覆盖人工写过的值）。")

    new, report = scope_migrate.plan(raw)
    problems = scope_migrate.validate(new)

    print("=" * 62)
    print("  迁移预演报告")
    print("=" * 62)
    print(f"  host 总数            {report['hosts']}")
    print(f"  反解出 cid           {report['with_cid']}")
    print(f"  反解出授权主体        {report['with_owner']}")
    print(f"  _说明 原文保留        {'是' if report['note_preserved'] else '否'}")
    print(f"  domains 已同步        {'是' if report['domains_synced'] else '否'}")
    print(f"  需人工复核            {len(report['needs_review'])} 条")
    for h in report["needs_review"][:40]:
        print(f"      - {h}")
    if problems:
        print(f"  [FAIL] 结构校验未通过：{problems}")
        return 1
    print("  结构校验             通过")
    print()

    if not apply:
        print("以上为预演，**未写盘**。确认无误后加 --apply 落盘。")
        return 0

    res = config_io.write_json_atomic(config.SCOPE_FILE, new)
    if not res["ok"]:
        print(f"[FAIL] 写入失败：{res['error']}")
        return 1
    config_io.audit("scope", "migrate", before={"domains": raw.get("domains")},
                    after={"domains": new.get("domains"),
                           "targets": len(new.get("targets") or [])},
                    level="high", actor="cli", note="migrate_scope.py --apply")
    print(f"[OK] 已写入 {config.SCOPE_FILE}")
    print(f"     备份：{res['backup'] or '（原本不存在，无备份）'}")
    print(f"     新哈希：{res['sha256_short']}（原 {res['before_sha256_short']}）")
    # 让操作者立刻看到「白名单还能正常读」——迁移最怕的就是把文件写坏导致全站被拒
    print(f"     复核：load_scope() 现在返回 {len(__import__('app.scope', fromlist=['x']).load_scope())} 个主机")
    return 0


if __name__ == "__main__":
    sys.exit(main())
