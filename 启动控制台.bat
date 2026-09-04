@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo ============================================================
echo   SRC 渗透 Agent - 本地控制台
echo ============================================================
echo.
echo   正在启动，浏览器会自动打开 http://127.0.0.1:8770
echo   关闭此窗口即停止服务。
echo.
echo   仅限已获得书面授权的目标测试。
echo ============================================================
echo.

rem Python 解释器探测顺序（可移植写法，不写死本机路径）：
rem   1. 环境变量 SRC_AGENT_PY 指定的解释器
rem   2. 项目内 .venv\Scripts\python.exe（.venv 已被 .gitignore 排除）
rem   3. PATH 中的 python
set "PY=%SRC_AGENT_PY%"
if "%PY%"=="" set "PY=%~dp0.venv\Scripts\python.exe"
if not exist "%PY%" set "PY=python"

rem DeepSeek 云端模型 API Key（前端模型切换用）。
rem 建议通过系统环境变量 DEEPSEEK_API_KEY 注入，不要将真实 Key 提交到公开仓库。
if not defined DEEPSEEK_API_KEY set "DEEPSEEK_API_KEY="

echo   使用解释器：%PY%
echo.

"%PY%" run.py
pause
