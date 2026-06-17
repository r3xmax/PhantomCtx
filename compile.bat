@echo off
setlocal

:: ============================================================
::  PhantomCtx - Build Script
::  Requires: MSVC (cl.exe) via Developer Command Prompt
:: ============================================================

set OUT_DIR=x64
set OUT_BIN=%OUT_DIR%\PhantomCtx.exe
set OUT_OBJ=%OUT_DIR%\

:: ------------------------------------------------------------

if not exist %OUT_DIR% (
    mkdir %OUT_DIR%
    echo [INFO] Created output directory: %OUT_DIR%
)

echo [INFO] Compiling PhantomCtx...

cl /nologo ^
    .\PhantomCtx\*.c ^
    .\PhantomCtx\utils\*.c ^
    .\PhantomCtx\recon\*.c ^
    .\PhantomCtx\common\*.c ^
    .\PhantomCtx\spawn\*.c ^
    .\PhantomCtx\runtime\*.c ^
    /Fe%OUT_BIN% /Fo%OUT_OBJ%

if %ERRORLEVEL% NEQ 0 (
    echo [!] Compilation failed.
    del /Q %OUT_DIR%\*.obj 2>nul
    exit /b 1
)

del /Q %OUT_DIR%\*.obj 2>nul
echo [SUCCESSFUL] Build successful: %OUT_BIN%
