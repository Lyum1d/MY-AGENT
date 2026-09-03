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

set PY=C:\Users\Lianaxber\.workbuddy\binaries\python\envs\src-agent\Scripts\python.exe

rem DeepSeek 云端模型 API Key（前端模型切换用）。在下方填入你的 Key，或通过系统环境变量注入。
rem 注意：不要将真实 Key 提交到公开仓库。
set DEEPSEEK_API_KEY=

if not exist "%PY%" (
    echo [错误] 未找到 Python 环境：%PY%
    echo 请先创建虚拟环境并安装依赖：
    echo   python -m venv C:\Users\Lianaxber\.workbuddy\binaries\python\envs\src-agent
    echo   pip install -r requirements.txt
    pause
    exit /b 1
)

"%PY%" run.py
pause
