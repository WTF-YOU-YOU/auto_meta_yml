@echo off
chcp 936 >nul 2>&1
title Clash Meta - 订阅合并工具
color 0A

echo ==================================================
echo         Clash Meta 订阅合并 一键运行工具
echo ==================================================
echo.

:: -------- 检测 Python --------
echo [1/3] 检测 Python 环境...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到 Python, 请先安装 Python 3.10+
    echo        下载地址: https://www.python.org/downloads/
    goto :end
)
for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do (
    echo        已找到 Python %%v
)
echo.

:: -------- 检测/安装依赖 --------
echo [2/3] 检测依赖库...
python -c "import requests; import yaml" >nul 2>&1
if %errorlevel% neq 0 (
    echo        正在安装缺失的依赖...
    pip install requests pyyaml -q
    if %errorlevel% neq 0 (
        echo [错误] 依赖安装失败, 请手动执行: pip install requests pyyaml
        goto :end
    )
    echo        依赖安装完成
) else (
    echo        依赖库已就绪
)
echo.

:: -------- 运行主脚本 --------
echo [3/3] 开始运行...
echo --------------------------------------------------
echo.
python "%~dp0fetch_proxies.py"
echo.

if %errorlevel% equ 0 (
    echo ==================================================
    echo   运行成功! 输出文件: outcome.meta.yml
    echo   请将该文件导入 Clash Verge 使用
    echo ==================================================
) else (
    echo ==================================================
    echo   [错误] 脚本运行失败, 请检查上方日志
    echo ==================================================
)

:end
echo.
pause
