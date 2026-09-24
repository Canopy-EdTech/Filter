@echo off
setlocal EnableDelayedExpansion

set "script_dir=%~dp0"
for %%I in ("%script_dir%..") do set "project_root=%%~fI"
set "default_output_dir=%project_root%\certs"

set /p "output_dir=Certificate output directory [%default_output_dir%]: "
if "%output_dir%"=="" set "output_dir=%default_output_dir%"

set /p "common_name=Certificate common name [Canopy Filter MITM CA]: "
if "%common_name%"=="" set "common_name=Canopy Filter MITM CA"

set /p "organization=Organization [Canopy EdTech]: "
if "%organization%"=="" set "organization=Canopy EdTech"

set /p "country=Country code [US]: "
if "%country%"=="" set "country=US"

set /p "validity_days=Validity in days [3650]: "
if "%validity_days%"=="" set "validity_days=3650"

set /p "key_size=RSA key size [4096]: "
if "%key_size%"=="" set "key_size=4096"

echo %validity_days%| findstr /r "^[1-9][0-9]*$" >nul
if errorlevel 1 (
	echo Validity must be a positive whole number. 1>&2
	exit /b 1
)

if not "%key_size%"=="2048" if not "%key_size%"=="3072" if not "%key_size%"=="4096" if not "%key_size%"=="8192" (
	echo Key size must be one of 2048, 3072, 4096, or 8192. 1>&2
	exit /b 1
)

echo %country%| findstr /r "^[A-Za-z][A-Za-z]$" >nul
if errorlevel 1 (
	echo Country must be a two-letter code. 1>&2
	exit /b 1
)

for /f "delims=" %%U in ('powershell -NoProfile -Command "'%country%'.ToUpper()"') do set "country=%%U"

set "ca_key=%output_dir%\ca.key"
set "ca_cert=%output_dir%\ca.crt"

set "existing="
if exist "%ca_key%" set "existing=1"
if exist "%ca_cert%" set "existing=1"

if defined existing (
	set /p "overwrite=Existing CA files found. Overwrite them? [y/N]: "
	if /i not "!overwrite!"=="y" (
		echo Aborted. Existing certificate files were not changed.
		exit /b 1
	)
)

if not exist "%output_dir%" mkdir "%output_dir%"

where openssl >nul 2>nul
if errorlevel 1 (
	echo openssl was not found on PATH. Install OpenSSL ^(e.g. via Git for Windows^) and try again. 1>&2
	exit /b 1
)

openssl genrsa -out "%ca_key%" %key_size%
if errorlevel 1 exit /b 1

openssl req -x509 -new -sha256 ^
	-key "%ca_key%" ^
	-out "%ca_cert%" ^
	-days %validity_days% ^
	-subj "/C=%country%/O=%organization%/CN=%common_name%" ^
	-addext "basicConstraints=critical,CA:TRUE,pathlen:1" ^
	-addext "keyUsage=critical,keyCertSign,cRLSign" ^
	-addext "subjectKeyIdentifier=hash"
if errorlevel 1 exit /b 1

echo.
echo MITM CA generated:
echo   Certificate: %ca_cert%
echo   Private key: %ca_key%
echo Install the certificate on client devices, and keep the private key secret.

endlocal
