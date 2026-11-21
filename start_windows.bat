@echo off

echo ========================================
echo DNS Monitor - Запуск системы
echo ========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [ОШИБКА] Python не установлен!
    echo Установите Python 3.7+ с https://www.python.org/
    pause
    exit /b 1
)

echo [1/4] Проверка зависимостей...
pip show flask >nul 2>&1
if errorlevel 1 (
    echo [!] Установка зависимостей...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo [ОШИБКА] Не удалось установить зависимости!
        pause
        exit /b 1
    )
)

echo [2/4] Подготовка окружения...
if not exist "templates" mkdir templates

echo [3/4] Запуск DNS-сервера на порту 5454...
start "DNS Server" /MIN python dns_server.py 5454

timeout /t 2 /nobreak >nul

echo [4/4] Запуск веб-интерфейса на порту 5000...
echo.
echo ========================================
echo DNS Monitor успешно запущен!
echo ========================================
echo.
echo DNS Server: localhost:5454
echo Web Interface: http://localhost:5000
echo.
echo Для остановки закройте это окно или нажмите Ctrl+C
echo.

python web_server.py

taskkill /FI "WindowTitle eq DNS Server*" /T /F >nul 2>&1

pause