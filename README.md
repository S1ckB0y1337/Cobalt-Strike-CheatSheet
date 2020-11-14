# Cobalt-Strike-Notes

General notes and advices for cobalt strike C2 framework.

## Summary

- [Cobalt Strike Notes](#cobalt-strike-notes)
  - [Summary](#summary)
  - [Basic Menu Explanation](#basic-menu-explanation)
  - [Listeners](#listeners)
  - [Malleable C2 Profiles](#malleable-c2-profiles)
  - [Aggressor Scripts](#aggressor-scripts)
  - [Common Commands](#common-commands)
  - [Exploitation](#exploitation)
  - [Privilege Escalation](#privilege-escalation)
  - [Pivoting](#pivoting)
  - [Lateral Movement](#lateral-movement)
  - [Exflitration](#exflitration)
  - [Miscellaneous](#miscellaneous)
  - [OPSEC Notes](#opsec-notes)
  
## Basic Menu Explanation

- **Cobalt Strike:** The first and most basic menu, it contains the functionality for connecting to a team server, set your preferences, change the view of beacon sessions, manage listeners and aggressor scripts.
- **View:** The view menu consists of elements that manages targets, logs, harvested credentials, screenshots, keystrokes etc. The main purpose of it is to provide an easy way to access the output of many modules, manage your loots and domain targets.
- **Attacks:** This menu contains numerous client side attack generating methods like phishing mails, website cloning and file hosting. Also provides numerous ways to generate your beacon payloads or just generate shellcode and save it for later use on another obfuscation tool.
- **Reporting:** It provides an easy way to generate pdf or spreadsheet files containing information about the execution of an attack, this way it assists you on organizing small reports, making the final report writing process easier.
- **Help:** Basic help menu of the tool.

## Listeners

### Egress Listeners

  - **HTTP/HTTPS:** The most basic payloads for beacon, by default the listeners will listen on ports 80 and 443 with always the option to set custom ports. You have the options to set proxy settings, customize the HTTP header or specify a bind port to redirect beacon's traffic if the infrastructure uses redirector servers for the payload callbacks.
  - **DNS:** A very stealthy payload options, provides stealthier traffic over the dns protocol, you need to specify the DNS server to connect to. The best situation to use this type of listener is in a really locked down environment that blocks even common traffic like port 80 and 443.

### Pivot Listeners

  - **TCP:** A basic tcp listener that bound on a spesific port.
  - **SMB:** An amazing option for internal spread and lateral move, this payload uses named pipes over the smb protocol and is the best approach to bypass firewalls when even default ports like 80 and 443 are black listed.

### Miscellaneous Listeners

  - **Foreign HTTP/HTTPS:** These type of listeners give us the option to pass a session from the metasploit framework to cobalt strike using either http or https payloads. A useful example is to execute an exploit module from metasploit and gain a beacon session on cobalt strike.
  - **External C2:** This is a special type of listener that gives the option to 3rd party applications to act as a communication medium for beacon.

## Malleable C2 Profiles
  In simple words a malleable c2 profile is a configuration file that defines how beacon will communicate and behave when executes    modules, spawns processes and threads, injects dlls or touches disk and memory. Not only that, but it configures how the payload's traffic will look like on a pcap, the communication interval and jitter etc.
  
  The big advantage of custom malleable c2 profiles, is that we can configure and customize our payload to match our situation and target environment, that way we make our selves more stealthy as we can blend with the environment's traffic.
  
## Aggressor Scripts
  Aggressor Script is the scripting language built into Cobalt Strike, version 3.0, and later. Aggresor Script allows you to modify and extend the Cobalt Strike client. These scripts can add additional functions on existing modules or create new ones. \
  [Aggressor Script Tutorial](https://www.cobaltstrike.com/aggressor-script/index.html)
  
## Common Commands
  - **help:** Listing of the available commands.
  - **help \<module>:** Show the help menu of the selected module.
  - **jobs:** List the running jobs of beacon.
  - **jobkill \<id>:** Kill selected job.
  - **run:** Execute OS commands using Win32 API calls.  
  - **shell:** Execute OS commands by spawning "cmd.exe /c".
  - **powershell:** Execute commands by spawning "powershell.exe"
   - **powershell-import:** Import a local powershell module in the current beacon process.
  - **powerpick:** Execute powershell commands without spawning "powershell.exe", using only .net libraries and assemblies. (Bypasses AMSI and CLM)
  - **drives:** List current system drives.
  - **getuid:** Get current user uid.
  - **sleep:** Set the interval and jitter of beacon's call back.
  - **ps:** Listing processes.
  - **cd:** Change directory.
  - **cp:** Copy a local file on another local location.
  - **download/upload:** Download a file and upload a local file.
  - **cancel:** Cancel a file download.
  - **reg:** Query Regisrty.
  
  
## Exploitation
  - **browserpivot:** Will hijack a web session of internet explorer and make possible for us to browse the web as the victim's browser, including it's sessions, cookies and saved passwords.
  - **dcsync:** Perform the DCsync attack using mimikatz.
  - **desktop:** Inject a VNC server on the beacon process and get a remote desktop view of the target.
  - **dllinject/dllload:** Inject a reflective dll into a process/Load a dll on current process.
  - **execute-assembly:** Loads and executes a .NET compiled assembly executable completely on memory.
  - **inject:** Inject a beacon payload on a specified process and spawn a new beacon session under it's security context.
  - **kerberos\*:** Manipulate kerberos tickets.
  - **ppid:** Spoofs the parent process of beacon for any post-exploitation child spawning job. That way we can hide our malicious post-exploitation jobs.
  - **psinject:** Inject on a specified process and execute a command using powerpick's functionality. \
  :notebook: Powershell modules imported with **powershell-import** are available.
  - **runu:** Run a command under a spoofed process PID.
  - **shinject:** Inject shellcode into another a running process.
  - **shspawn:** Create a new process and inject shellcode into it.
  
  
  ## Privilege Escalation
  - **elevate:** Contains numerous ways to escalate your privileges to Administrator or SYSTEM using kernel exploits and UAC bypasses.
  - **getsystem:** Attempts to impersonate system, if it fails we can use steal_token to steal a token from a process that runs as SYSTEM.
  - **getprivs:** Same as metasploit's function, enables all the available privileges on the current token.
  - **runasadmin:** Attempts to run a command on an elevated context of Administrator or SYSTEM using a local kernel or UAC bypass exploit. The difference with elevate is that it doesnt spawn a new beacon, but executes a specified application of our choice under the new context.
  
  ## Pivoting
  - **socks:** Start a socks4a proxy server and listen on a specified port. Access through the proxy server can achieved using a proxy client like proxychains or redsocks.
  - **covertvpn:** Deploy a VPN on the current system, will create a new interface and merge it into a specified IP. Using this we can use a local interface to access the internal target network like we would do if we had a real connection through a router.
  
  ## Lateral Movement
  - **portscan:** Performs a portscan on a spesific target.
  - **runas:** A wrapper of runas.exe, using credentials you can run a command as another user.
  - **pth:** By providing a username and a NTLM hash you can perform a Pass The Hash attack and inject a TGT on the current process. \
  :exclamation: This module needs Administrator privileges.
  - **steal_token:** Steal a token from a specified process.
  - **make_token:** By providing credentials you can create an impersonation token into the current process and execute commands from the context of the impersonated user.
  - **jump:** Provides easy and quick way to move lateraly using winrm or psexec to spawn a new beacon session on a target. \
  :exclamation: The **jump** module will use the current delegation/impersonation token to authenticate on the remote target. \
  :muscle: We can combine the **jump** module with the **make_token** or **pth** module for a quick "jump" to another target on the network.
  - **remote-exec:** Execute a command on a remote target using psexec, winrm or wmi. \
  :exclamation: The **remote-exec** module will use the current delegation/impersonation token to authenticate on the remote target.
  - **ssh/ssh-key:** Authenticate using ssh with password or private key. Works for both linux and windows hosts. It gives you basic ssh functionality with some additional post exploitation modules.
  
  ## Exflitration
  - **hashdump:** Dump the local SAM hive's NTLM hashes. This only dumps local machine user credentials.
  - **keylogger:** Will capture keystrokes of a specified process and save them on a database.
  - **screenshot:** Will capture the screen of a current process and save it on the database.
  - **logonpassword:** Executes the well know **logonpasswords** function of mimikatz on the current machine. This function of course uses process injection so isn't OPSEC safe, use it with precaution.
  - **mimikatz:** You can execute any function of mimikatz, mimikatz driver functionality is not included.

  ## Miscellaneous
   - **spawn:** Spawn a new beacon on the current machine, you can choose any type of listener you want.
   - **spawnas:** Spawn a new beacon on the current machine as another user by providing credentials.
   - **spawnto:** Sets the executable that beacon will use to spawn and inject shellcode into it for it's post-exploitation functionality. You must specify a full path to the executable.
   - **spawnu:** Attempt to spawn a session with a spoofer PID as its parent, the context of the process will match the identity of the specified PID.
   - **argue:** Will mask/spoof the arguments of a malicious command of our choice with legitimate ones.
   - **blockdlls:** This module will create and set a custom policy on beacon's child processes that will block the injection of any 3rd party dll that is not signed by microsoft, that way we can block any blue team tool that uses dll injection to inspect and kill malicious processes and actions.
   - **timestomp:** Tamper the timestamp of a file, by applying another file's timestamp.

## OPSEC Notes
 - **Session Prepping:** Before engaging in any post-exploitation action after we have compromised a host, we should prepare our beacon to match the environments behaviour, that way we will generate the less amount of IOCs (Indicators Of Compromise) we can. To do that we can the "spawnto" module to specify which binary our child processes will use to execute post exploitation actions, also we can use the "ppid" module to spoof the parent process that our child processes will spawn under. Both those tricks will provide us with a good amount of stealth and will hide our presence on the compromised host.
 - **Environment Behaviour Blending:** On a post exploitation context even when we are using the http(s) protocols to blend in with the environment's traffic, a good endpoint security solution or a Next Generation firewall can figure out that some traffic is unusual to exist on this environment and will probably block and create telemetry to a SOC endpoint for the blue team to examine it. Thats where "Malleable C2" profiles come, it is a configuration file that each cobalt strike team server can use and it provides customization and flexibility for: beacon's traffic, process injection, process spawning, behaviour, antivirus evasion etc. So the best practise is to never use default beacon behaviour and always use a custom profile for every assessment.
   
## EDR Evasion Tools and Methods
  - [PEzor](https://github.com/phra/PEzor): PE Packer for EDR evasion.
  - [SharpBlock](https://github.com/CCob/SharpBlock): A method of bypassing EDR's active projection DLL's by preventing entry point execution.
  - [TikiTorch](https://github.com/rasta-mouse/TikiTorch): AV/EDR evasion using Process Hollowing Injection.
  - [Donut](https://github.com/TheWover/donut): Donut is a position-independent code that enables in-memory execution of VBScript, JScript, EXE, DLL files and dotNET assemblies.
  - [Dynamic-Invoke](https://thewover.github.io/Dynamic-Invoke/): Bypassing EDR solution by hiding malicious win32 API calls from within C# managed code.
   
## General Post-Exploitation TIPS
  - Before executing anything be sure you know how it behaves and what IOCs (Indicators Of Compromise) it generates.
  - Try to not touch disk as much as you can and operate in memory for the most part.
  - Check AppLocker policies to determine what type of files you can execute and from which locations.
  - Clean up artifacts immediately after finishing a post-exploitation task.
  - Clean event logs after finishing with a host.
  
