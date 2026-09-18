# -*- coding: utf-8 -*-
"""出网限速（唯一实现）。

背景：节流此前只存在于 HTTP 重放器（app/replayer.py 的 _rate_limit / REPLAY_MIN_INTERVAL），
而命令行扫描器（app/executor.py）与 split_task 的并发完全没有速率上限。两条路径各算各的
计时，对同一目标的实际请求速率是两者之和，与项目「禁止高频扫描、不得影响业务可用性」
的红线不匹配。这里收敛为唯一实现，重放与扫描共用同一把锁、同一份计时。

设计取舍：
  · 按 key（主机名）各持一把锁：同一目标串行，不同目标之间仍可并发，
    不至于把整个平台降级成单线程。
  · 另有一道全局闸（GLOBAL_MIN_INTERVAL）限制整机出网动作的频率，
    防止「多目标 × 多子任务」叠出瞬时高峰。
  · 计时状态放在模块级：进程内共享，不随调用方变化。

注意：本模块只做「速率」控制，不做授权判断——授权边界在 app/scope.py。
"""
from __future__ import annotations

import asyncio
import time

# key -> 该目标自己的锁与上次动作时刻
_key_locks: dict[str, asyncio.Lock] = {}
_key_last: dict[str, float] = {}

# 整机出网闸
_global_lock = asyncio.Lock()
_global_last = 0.0


async def acquire(key: str, min_interval: float, global_interval: float = 0.0) -> None:
    """在执行某个出网动作之前调用。

    key 建议传主机名（同一主机共享节流）；min_interval 为该 key 两次动作的最小间隔（秒）；
    global_interval > 0 时额外限制整机出网动作间隔。
    """
    global _global_last

    if global_interval > 0:
        async with _global_lock:
            wait = global_interval - (time.time() - _global_last)
            if wait > 0:
                await asyncio.sleep(wait)
            _global_last = time.time()

    if min_interval <= 0:
        return

    lock = _key_locks.get(key)
    if lock is None:
        lock = asyncio.Lock()
        _key_locks[key] = lock
    async with lock:
        wait = min_interval - (time.time() - _key_last.get(key, 0.0))
        if wait > 0:
            await asyncio.sleep(wait)
        _key_last[key] = time.time()


def reset() -> None:
    """清空计时状态（仅供测试使用）。"""
    global _global_last
    _key_locks.clear()
    _key_last.clear()
    _global_last = 0.0
