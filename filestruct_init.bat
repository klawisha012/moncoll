@echo off
:: Создание папок
if not exist "etc\angie\modsecurity" mkdir "etc\angie\modsecurity"
if not exist "etc\angie\http.d" mkdir "etc\angie\http.d"
if not exist "etc\angie\geoip2" mkdir "etc\angie\geoip2"
if not exist "etc\vector" mkdir "etc\vector"
if not exist "var\log\angie" mkdir "var\log\angie"

:: Копирование данных из Docker
docker compose cp -L angie:/etc/angie/modsecurity/. ./etc/angie/modsecurity
docker compose cp -L angie:/etc/angie/http.d/. ./etc/angie/http.d
docker compose cp -L angie:/etc/angie/geoip2/. ./etc/angie/geoip2

docker compose cp -L angie:/etc/angie/ ./etc/angie/
docker compose cp -L angie:/usr/lib/angie/modules/ ./etc/angie/modules/
docker compose cp -L vector:/etc/vector/ ./etc/vector/

:: Сборка
docker build -f angie.Dockerfile -t angie-modsec-crs:3.3.5 .

echo Operation completed!
pause