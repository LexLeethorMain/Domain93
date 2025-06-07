# ─── Startup & Dependency Check ──────────────────────────────────────────────
import sys
import subprocess
import os

# List of required packages -> (import_name, package_name_for_pip)
REQUIRED_PACKAGES = [
    ('art', 'art'),
    ('PIL', 'Pillow'),
    ('requests', 'requests'),
    ('pytesseract', 'pytesseract'),
    ('lolpython', 'lolpython'),
    ('stem', 'stem'),
    ('ttkbootstrap', 'ttkbootstrap')
]

def check_and_install_dependencies():
    """
    Checks if the required Python packages are installed, and if not,
    attempts to install them using pip.
    """
    print("-" * 60)
    print("Checking for required packages...")
    
    for import_name, package_name in REQUIRED_PACKAGES:
        try:
            __import__(import_name)
            print(f" {package_name} is already installed.")
        except ImportError:
            print(f" {package_name} not found. Attempting to install...")
            try:
                # Use sys.executable to ensure pip is from the correct Python env
                # Redirect output to DEVNULL to keep the console clean
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", package_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
                print(f"Successfully installed {package_name}.")
            except subprocess.CalledProcessError:
                print(f"Failed to install {package_name}.")
                print("Please install it manually using the command:")
                print(f"{os.path.basename(sys.executable)} -m pip install {package_name}")
                sys.exit(1) # Exit if a crucial dependency can't be installed
            except FileNotFoundError:
                 print("      [ERROR] 'pip' is not available. Please ensure pip is installed.")
                 sys.exit(1)
                 
    print("All dependencies are satisfied.")
    print("-" * 60)

# Run the dependency check right at the start
check_and_install_dependencies()

print("Starting Domain93 GUI...")
# ───────────────────────────────────────────────────────────────────────────────


import os
import sys
import time
import threading
import subprocess
import platform
from io import BytesIO
from art import *
from PIL import Image, ImageFilter
import socket
import copy
import re
import random
import string
import requests as req
import freedns
import pytesseract
import lolpython
from importlib.metadata import version
from stem import Signal
from stem.control import Controller

import tkinter as tk
from tkinter import ttk as tk_ttk # To avoid conflict with ttkbootstrap
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

# ─── Helper: log/output to the ScrolledText widget ─────────────────────────────

log_widget = None

def log(msg, style=""):
    """
    Append a line to the ScrolledText output.
    style is ignored here but could be used to change tag.
    """
    global log_widget
    if not log_widget:
        return
    log_widget.configure(state="normal")
    log_widget.insert(tk.END, msg + "\n")
    log_widget.see(tk.END)
    log_widget.configure(state="disabled")

# ─── Tor management ──────────────────────────────────────────────────────────────

tor_process = None

def start_tor():
    """
    Locate tor.exe at ./tor/tor/tor.exe (relative to this file),
    launch it with control port, and wait until the SOCKS5 port (127.0.0.1:9050) is listening.
    """
    global tor_process
    if tor_process is not None:
        log("[INFO] Tor is already running.")
        return True

    # 1) Build the path to tor.exe relative to this script:
    script_dir = os.path.dirname(__file__)
    tor_path = os.path.join(script_dir, "tor", "tor", "tor.exe")
    tor_data_dir = os.path.join(script_dir, "tor_data")

    # Create tor data directory if it doesn't exist
    os.makedirs(tor_data_dir, exist_ok=True)

    if not os.path.isfile(tor_path):
        log(f"[ERROR] tor.exe not found at {tor_path}.")
        return False

    # 2) Launch tor.exe with control port and cookie authentication
    try:
        tor_process = subprocess.Popen(
            [
                tor_path,
                "--quiet",
                "--SocksPort", "9050",
                "--ControlPort", "9051",
                "--DataDirectory", tor_data_dir,
                "--CookieAuthentication", "1",
                "--SocksTimeout", "60",
                "--NewCircuitPeriod", "60",
                "--MaxCircuitDirtiness", "60"
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        log(f"[INFO] Launched Tor subprocess (PID={tor_process.pid}). Waiting for it to start...")
    except Exception as e:
        log(f"[ERROR] Failed to start Tor: {e}")
        tor_process = None
        return False

    # 3) Wait for Tor to be ready (both SOCKS and control port)
    start_ts = time.time()
    socks_ready = False
    control_ready = False

    while True:
        if time.time() - start_ts > 30:  # 30 second timeout
            if not socks_ready:
                log("[ERROR] Tor did not bind to 127.0.0.1:9050 within 30 seconds.")
            if not control_ready:
                log("[ERROR] Tor control port did not become ready in time.")
            stop_tor()
            return False

        # Check SOCKS port (9050)
        if not socks_ready:
            try:
                s = socket.create_connection(("127.0.0.1", 9050), timeout=1)
                s.close()
                log("[INFO] Tor SOCKS5 proxy is ready on 127.0.0.1:9050")
                socks_ready = True
            except (ConnectionRefusedError, OSError):
                pass

        # Check control port (9051)
        if not control_ready:
            try:
                s = socket.create_connection(("127.0.0.1", 9051), timeout=1)
                s.close()
                log("[INFO] Tor control port is ready on 127.0.0.1:9051")
                control_ready = True
            except (ConnectionRefusedError, OSError):
                pass

        if socks_ready and control_ready:
            log("[INFO] Tor is fully initialized and ready to use.")
            return True

        time.sleep(0.5)


def change_tor_identity():
    """
    Change the Tor circuit to get a new identity.
    Returns True if successful, False otherwise.
    """
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()
            controller.signal(Signal.NEWNYM)
            # Wait for the new circuit to be established
            time.sleep(controller.get_newnym_wait() or 5)
            return True
    except Exception as e:
        log(f"[ERROR] Failed to change Tor identity: {e}")
        return False


def stop_tor():
    """
    Terminate the Tor subprocess if it was started.
    """
    global tor_process
    if tor_process:
        try:
            tor_process.terminate()
            tor_process.wait(timeout=5)
            log("[INFO] Tor subprocess stopped.")
        except subprocess.TimeoutExpired:
            log("[WARNING] Tor process did not terminate gracefully, forcing...")
            tor_process.kill()
            tor_process.wait()
            log("[INFO] Tor process was force stopped.")
        except Exception as e:
            log(f"[ERROR] Error stopping Tor process: {e}")
        finally:
            tor_process = None


# ─── Resource path helper ────────────────────────────────────────────────────────

def resource_path(relative_path):
    """
    Get absolute path to resource, whether running as script or PyInstaller bundle.
    """
    if getattr(sys, 'frozen', False):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.abspath(relative_path)

# ─── Domain93 logic (mostly unchanged, just reading from GUI controls) ───────────

# We will store “arguments” in a simple namespace object instead of argparse.
class Args:
    def __init__(self):
        self.ip = ""
        self.number = None
        self.webhook = ""
        self.proxy = None
        self.use_tor = False
        self.silent = False
        self.outfile = "domainlist.txt"
        self.type = "A"
        self.pages = ""
        self.subdomains = "random"
        self.auto = False
        self.single_tld = ""
args = Args()

client = freedns.Client()

def get_data_path():
    """
    Determine which Tesseract binary to use based on OS.
    """
    script_dir = os.path.dirname(__file__)
    if platform.system() == "Windows":
        filename = os.path.join(script_dir, "data", "windows", "tesseract.exe")
    elif platform.system() == "Linux":
        filename = os.path.join(script_dir, "data", "tesseract-linux")
    else:
        log("[WARN] Unsupported OS. Captcha-solving may fail.")
        return None
    os.environ["TESSDATA_PREFIX"] = os.path.join(script_dir, "data")
    return filename

# Initialize Tesseract path
tess_path = get_data_path()
if tess_path:
    pytesseract.pytesseract.tesseract_cmd = tess_path
else:
    log("[WARN] No valid Tesseract binary found.")

domainlist = []
domainnames = []

def getpagelist(arg):
    arg = arg.strip()
    if "," in arg:
        pagelist = []
        for item in arg.split(","):
            if "-" in item:
                sp, ep = item.split("-")
                sp, ep = int(sp), int(ep)
                if sp < 1 or sp > ep:
                    log(f"[ERROR] Invalid page range: {item}")
                    sys.exit(1)
                pagelist.extend(range(sp, ep + 1))
            else:
                pagelist.append(int(item))
        return pagelist
    elif "-" in arg:
        sp, ep = arg.split("-")
        sp, ep = int(sp), int(ep)
        if sp < 1 or sp > ep:
            log(f"[ERROR] Invalid page range: {arg}")
            sys.exit(1)
        return list(range(sp, ep + 1))
    else:
        return [int(arg)]

def getdomains(arg):
    global domainlist, domainnames
    for sp in getpagelist(arg):
        log(f"[INFO] Getting page {sp}...")
        html = req.get(
            f"https://freedns.afraid.org/domain/registry/?page={sp}&sort=2&q=",
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept-Language": "en-US,en;q=0.9",
                "Cache-Control": "max-age=0",
                "Connection": "keep-alive",
                "DNT": "1",
                "Host": "freedns.afraid.org",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": "Mozilla/5.0",
            },
        ).text
        pattern = r"<a href=\/subdomain\/edit\.php\?edit_domain_id=(\d+)>([\w.-]+)<\/a>(.+\..+)<td>public<\/td>"
        matches = re.findall(pattern, html)
        for match in matches:
            domainlist.append(match[0])
            domainnames.append(match[1])
        log(f"[INFO] Found {len(matches)} domains on page {sp}.")

def find_domain_id(domain_name):
    page = 1
    html = req.get(
        f"https://freedns.afraid.org/domain/registry/?page={page}&q={domain_name}",
        headers={
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/jxl,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-US,en;q=0.9",
            "Cache-Control": "max-age=0",
            "Connection": "keep-alive",
            "DNT": "1",
            "Host": "freedns.afraid.org",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0",
        },
    ).text
    pattern = r"<a href=\/subdomain\/edit\.php\?edit_domain_id=([0-9]+)><font color=red>(?:.+\..+)<\/font><\/a>"
    matches = re.findall(pattern, html)
    if matches:
        log(f"[INFO] Found domain ID: {matches[0]}")
        return matches[0]
    raise Exception("Domain ID not found")

def getcaptcha():
    return Image.open(BytesIO(client.get_captcha()))

def denoise(img):
    imgarr = img.load()
    newimg = Image.new("RGB", img.size)
    newarr = newimg.load()
    dvs = []
    for y in range(img.height):
        for x in range(img.width):
            r, g, b = imgarr[x, y]
            if (r, g, b) == (255, 255, 255):
                newarr[x, y] = (r, g, b)
            elif ((r + g + b) / 3) == 112:
                newarr[x, y] = (255, 255, 255)
                dvs.append((x, y))
            else:
                newarr[x, y] = (0, 0, 0)

    backup = copy.deepcopy(newimg).load()
    for y in range(img.height):
        for x in range(img.width):
            if newarr[x, y] == (255, 255, 255):
                continue
            black_neighbors = 0
            for ny in range(max(0, y - 2), min(img.height, y + 2)):
                for nx in range(max(0, x - 2), min(img.width, x + 2)):
                    if backup[nx, ny] == (0, 0, 0):
                        black_neighbors += 1
            if black_neighbors <= 5:
                newarr[x, y] = (255, 255, 255)

    for x, y in dvs:
        black_neighbors = 0
        for ny in range(max(0, y - 2), min(img.height, y + 2)):
            for nx in range(max(0, x - 1), min(img.width, x + 1)):
                if newarr[nx, ny] == (0, 0, 0):
                    black_neighbors += 1
            if black_neighbors >= 5:
                newarr[x, y] = (0, 0, 0)
            else:
                newarr[x, y] = (255, 255, 255)

    backup = copy.deepcopy(newimg).load()
    for y in range(img.height):
        for x in range(img.width):
            if newarr[x, y] == (255, 255, 255):
                continue
            black_neighbors = 0
            for ny in range(max(0, y - 2), min(img.height, y + 2)):
                for nx in range(max(0, x - 2), min(img.width, x + 2)):
                    if backup[nx, ny] == (0, 0, 0):
                        black_neighbors += 1
            if black_neighbors <= 6:
                newarr[x, y] = (255, 255, 255)
    return newimg

def solve(image):
    """
    Run multiple OCR “strategies” on the same image until we get
    a 4- or 5-character result. If every strategy fails, grab a new
    captcha and try again.
    """
    # First, denoise the image once up front
    image = denoise(image)

    # Define a list of (filter_pipeline, tesseract_config, post_regex) tuples.
    # Each entry is one “try” with its own preprocessing & psm.
    strategies = [
        # Strategy 1: light blur → convert to 1-bit → rank filter
        (
            lambda im: im.filter(ImageFilter.GaussianBlur(1))
                            .convert("1")
                            .filter(ImageFilter.RankFilter(3, 3)),
            "-c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ --psm 7",
            r"[^A-Z]"
        ),
        # Strategy 2: stronger blur → median filter
        (
            lambda im: im.filter(ImageFilter.GaussianBlur(2))
                            .filter(ImageFilter.MedianFilter(3)),
            "-c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ --psm 8",
            r"[^A-Za-z]"
        ),
        # Strategy 3: raw image, no binarization
        (
            lambda im: im,
            "-c tessedit_char_whitelist=ABCDEFGHIJKLMNOPQRSTUVWXYZ --psm 8",
            r"[^A-Za-z]"
        ),
    ]

    for idx, (pre_fn, config, regex) in enumerate(strategies, start=1):
        try:
            processed = pre_fn(image)
            text = pytesseract.image_to_string(processed, config=config)
            # strip any non-letters
            text = re.sub(regex, "", text).upper()
        except Exception as e:
            log(f"Strategy {idx} raised an error: {e}")
            text = ""

        log(f"Strategy {idx} ➔ OCR result: {text}")

        if len(text) in (4, 5):
            return text  # success!

        log(f"Strategy {idx} failed (got {len(text)} chars).")

    # If we reach here, none of the strategies yielded 4 or 5 chars:
    log("Captcha failed.")
    return "Failed"


def generate_random_string(length):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(length))

def login(change_identity=False):
    """
    Handle account creation and login.
    
    Args:
        change_identity: If True and using Tor, change Tor identity before creating new account
    """
    if change_identity and args.use_tor:
        log("[INFO] Changing Tor identity before creating new account...")
        change_tor_identity()

    while True:
        try:
            log("[INFO] Fetching captcha...")
            image = getcaptcha()
            if args.auto:
                captcha = solve(image)
                log(f"[INFO] Captcha solved: {captcha}")
            else:
                log("[INFO] Showing captcha window... Please enter code in the console.")
                image.show()
                captcha = input("Enter captcha: ")

            log("[INFO] Generating temporary email...")
            mailresp = req.get("https://api.guerrillamail.com/ajax.php?f=get_email_address").json()
            email = mailresp["email_addr"]
            log(f"[INFO] Using email: {email}")

            username = generate_random_string(13)
            client.create_account(
                captcha,
                generate_random_string(13),
                generate_random_string(13),
                username,
                "pegleg1234",
                email,
            )
            log("[INFO] Activation email sent, waiting...")

            # Wait for activation email with timeout
            start_time = time.time()
            while time.time() - start_time < 120:  # 2 minute timeout
                check = req.get(
                    f"https://api.guerrillamail.com/ajax.php?f=check_email&seq=0&sid_token={mailresp['sid_token']}",
                    timeout=30
                ).json()
                if int(check["count"]) > 0:
                    mail = req.get(
                        f"https://api.guerrillamail.com/ajax.php?f=fetch_email&email_id={check['list'][0]['mail_id']}&sid_token={mailresp['sid_token']}",
                        timeout=30
                    ).json()
                    match = re.search(r'\?([^">]+)"', mail["mail_body"])
                    if match:
                        code = match.group(1)
                        log(f"[INFO] Received activation code: {code}")
                        client.activate_account(code)
                        log("[INFO] Account activated, logging in...")
                        time.sleep(1)
                        client.login(email, "pegleg1234")
                        log("[INFO] Login successful.")
                        return True  # Success
                    else:
                        log("[ERROR] Activation code not found in email.")
                        break
                time.sleep(5)  # Check every 5 seconds
            else:
                log("[ERROR] Timed out waiting for activation email")
                return False

        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            log(f"[ERROR] While creating account: {e}")
            time.sleep(5)
            continue

def createdomain():
    while True:
        try:
            hookbool = bool(args.webhook)
            webhook = args.webhook if hookbool else ""

            image = getcaptcha()
            if args.auto:
                capcha = solve(image)
                log("Captcha solved")
            else:
                log("Showing captcha... Please enter code in the console.")
                image.show()
                capcha = input("Enter the captcha code: ")

            if args.single_tld:
                random_domain_id = non_random_domain_id
            else:
                random_domain_id = random.choice(domainlist)
            if args.subdomains == "random":
                subdomainy = generate_random_string(10)
            else:
                subdomainy = random.choice(args.subdomains.split(","))

            ip_address = args.ip or "172.93.102.156"
            client.create_subdomain(capcha, args.type, subdomainy, random_domain_id, ip_address)

            tld = args.single_tld or domainnames[domainlist.index(random_domain_id)]
            domain_url = f"http://{subdomainy}.{tld}"

            log(f"Domain created: {domain_url}")

            with open(args.outfile, "a") as domainsdb:
                domainsdb.write(f"{domain_url}\n")

            if hookbool:
                log("Notifying webhook...")
                try:
                    req.post(
                        webhook,
                        json={"content": f"Domain created:\n{domain_url}\nIP: {ip_address}"},
                        timeout=10
                    )
                    log("Webhook notified.")
                except Exception as e:
                    log(f"Failed to notify webhook: {e}")
        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            log("Got error while creating domain: " + repr(e))
            continue
        else:
            break

def createlinks(number):
    for i in range(number):
        if i % 5 == 0:
            if args.use_tor:
                log("[INFO] Starting new account batch - changing Tor identity...")
                change_tor_identity()

            login(change_identity=False)

        createdomain()

def init_flow():
    """
    Main entry point that reads from GUI controls and runs the logic.
    """
    global non_random_domain_id

    # Read GUI controls:
    args.ip = ip_entry.get().strip()
    args.number = int(num_entry.get()) if num_entry.get().strip().isdigit() else None
    args.webhook = webhook_entry.get().strip()
    args.proxy = proxy_entry.get().strip() or None
    args.use_tor = bool(var_use_tor.get())
    args.outfile = outfile_entry.get().strip() or "domainlist.txt"
    args.type = type_var.get()
    args.pages = pages_entry.get().strip() or "1-10"
    args.subdomains = subdomains_entry.get().strip() or "random"
    args.auto = bool(var_auto.get())
    args.single_tld = single_tld_entry.get().strip()

    # Set up proxies/Tor:
    if args.use_tor:
        if not start_tor(): return # Exit if Tor fails to start
        client.session.proxies.update({
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050",
        })
        log("[INFO] Using Tor proxy for all requests.")
    elif args.proxy:
        client.session.proxies.update({"http": args.proxy, "https": args.proxy})
        log(f"[INFO] Using HTTP proxy: {args.proxy}")

    # Fetch domain list or specific domain ID:
    non_random_domain_id = None
    if args.single_tld:
        try:
            log(f"Searching for TLD: {args.single_tld}...")
            non_random_domain_id = find_domain_id(args.single_tld)
        except Exception as e:
            log(f"[ERROR] Could not find TLD '{args.single_tld}': {e}")
            return
    else:
        try:
            log(f"Fetching domains from pages: {args.pages}...")
            getdomains(args.pages)
            log(f"[INFO] Total domains fetched: {len(domainlist)}")
        except Exception as e:
            log(f"[ERROR] Failed to fetch domain list: {e}")
            return

    # Create domains:
    if args.number:
        createlinks(args.number)
    else:
        login()
        for _ in range(5):
            createdomain()

    if args.use_tor:
        stop_tor()

    log("✓ All tasks completed.")

# ─── Data for UI ─────────────────────────────────────────────────────────────────

PRESET_IPS = {
    "Onyx": "172.67.158.114", "Plexile Arcade": "216.24.57.1", "Comet/PXLNOVA": "172.66.46.221",
    "Bolt": "104.36.86.24", "BrunysIXLWork": "185.211.4.69", "Rammerhead IP": "108.181.32.77",
    "GlacierOS (A)": "66.241.124.98", "Duckflix": "104.21.54.237", "Canlite (3kh0 v5)": "104.36.85.249",
    "Lunaar": "164.152.26.189", "Interstellar": "66.23.193.126", "The Pizza Edition": "104.36.84.31",
    "Light": "104.243.45.193", "Velara": "185.211.4.69", "DuckHTML": "104.167.215.179",
    "Breakium": "172.93.100.82", "Kazwire 1": "209.222.97.244", "Mocha": "45.88.186.218",
    "Astro": "104.243.37.85", "FalconLink": "104.243.43.17", "Boredom": "152.53.36.42",
    "Nowgg.lol": "152.53.80.35", "Moonlight": "172.93.104.11", "Sunset": "107.206.53.96",
    "Emerald/Phantom Games/G1mkit": "66.23.198.136", "Kazwire 2": "103.195.102.132",
    "Astroid": "5.161.68.227", "Shadow": "104.243.38.18", "Space": "104.243.38.145",
    "Szvy Central": "152.53.38.100", "Croxy Proxy 1": "157.230.79.247",
    "Croxy Proxy 2": "143.244.204.138", "Croxy Proxy 3": "157.230.113.153",
    "Seraph": "15.235.166.92", "Hdun": "109.204.188.135", "Selenite": "65.109.112.222"
}
CUSTOM_IP_OPTION = "Enter Custom IP..."

# Define global UI elements to be accessible in init_flow and main
ip_entry = None
num_entry = None
webhook_entry = None
proxy_entry = None
var_use_tor = None
outfile_entry = None
type_var = None
pages_entry = None
subdomains_entry = None
var_auto = None
single_tld_entry = None
preset_combo = None

def main():
    """The main entry point for the application."""
    global log_widget, ip_entry, num_entry, webhook_entry, proxy_entry, var_use_tor, outfile_entry
    global type_var, pages_entry, subdomains_entry, var_auto, single_tld_entry, preset_combo

    root = ttk.Window(themename="cyborg")
    root.title("Domain93 GUI")
    root.geometry("1200x850")
    root.minsize(1000, 750)

    # Create a new custom style for the button
    style = ttk.Style()
    style.configure('large.success.TButton', font=("Segoe UI Variable", 14, "bold"))

    # --- Main layout frames ---
    # Sidebar container
    sidebar_container = ttk.Frame(root)
    sidebar_container.pack(side="left", fill="y", expand=False)

    # Main output frame
    output_frame = ttk.Frame(root, padding=(20, 20, 20, 10))
    output_frame.pack(side="right", fill="both", expand=True)

    # --- Create a scrollable sidebar ---
    # Canvas for scrolling
    canvas = tk.Canvas(sidebar_container, width=375, highlightthickness=0, bg=style.colors.get('bg'))
    canvas.pack(side="left", fill="both", expand=True)

    # Scrollbar
    scrollbar = ttk.Scrollbar(sidebar_container, orient="vertical", command=canvas.yview)
    scrollbar.pack(side="right", fill="y")
    canvas.configure(yscrollcommand=scrollbar.set)

    # Frame to hold the actual sidebar content (this is what will scroll)
    sidebar = ttk.Frame(canvas, padding=(20, 0))
    sidebar_frame_id = canvas.create_window((0, 0), window=sidebar, anchor="nw")

    def on_sidebar_configure(event):
        # Update the scroll region to encompass the inner frame
        canvas.configure(scrollregion=canvas.bbox("all"))

    def on_canvas_configure(event):
        # Update the width of the inner frame to match the canvas
        canvas.itemconfig(sidebar_frame_id, width=event.width)

    sidebar.bind("<Configure>", on_sidebar_configure)
    canvas.bind("<Configure>", on_canvas_configure)


    # --- Callback for Preset Selection ---
    def on_preset_selected(event):
        selected_preset = preset_combo.get()
        ip_entry.delete(0, tk.END)
        if selected_preset == CUSTOM_IP_OPTION:
            return
        ip_address = PRESET_IPS.get(selected_preset, "")
        ip_entry.insert(0, ip_address)

    # ─── Sidebar widgets (now packed into the 'sidebar' frame) ───────────────────

    # Title
    ttk.Label(sidebar, text="Domain93", font=("Segoe UI Variable", 22, "bold")).pack(pady=(10, 5), anchor="w")
    ttk.Label(sidebar, text="Automated Domain Creator", font=("Segoe UI Variable", 10), bootstyle="secondary").pack(anchor="w")
    ttk.Separator(sidebar, bootstyle="secondary").pack(fill="x", pady=20, anchor="w")

    # --- Control Groups ---
    # Network & Destination Group
    net_group = ttk.Labelframe(sidebar, text="Network & Destination", padding=15)
    net_group.pack(fill='x', pady=5)

    ttk.Label(net_group, text="Select a Preset").pack(fill='x', pady=(0,5))
    preset_combo = ttk.Combobox(
        net_group,
        values=[CUSTOM_IP_OPTION] + list(PRESET_IPS.keys()),
        bootstyle="dark"
    )
    preset_combo.pack(fill='x', pady=(0, 10))
    preset_combo.current(0)
    preset_combo.bind("<<ComboboxSelected>>", on_preset_selected)

    ttk.Label(net_group, text="Destination IP Address (or enter custom)").pack(fill='x', pady=(0,5))
    ip_entry = ttk.Entry(net_group, bootstyle="dark")
    ip_entry.pack(fill='x', pady=(0, 10))

    ttk.Label(net_group, text="Record Type").pack(fill='x', pady=(0,5))
    type_var = tk.StringVar(value="A")
    type_menu = ttk.OptionMenu(net_group, type_var, "A", "A", "AAAA", "CNAME", "TXT", bootstyle="dark-outline")
    type_menu.pack(fill='x')

    # Domain Source Group
    source_group = ttk.Labelframe(sidebar, text="Domain Source", padding=15)
    source_group.pack(fill='x', pady=(10, 5))

    ttk.Label(source_group, text="Pages to Scrape (e.g., 1-10)").pack(fill='x', pady=(0,5))
    pages_entry = ttk.Entry(source_group, bootstyle="dark")
    pages_entry.insert(0, "1-10")
    pages_entry.pack(fill='x', pady=(0, 10))

    ttk.Label(source_group, text="Subdomains (comma-sep or 'random')").pack(fill='x', pady=(0,5))
    subdomains_entry = ttk.Entry(source_group, bootstyle="dark")
    subdomains_entry.insert(0, "random")
    subdomains_entry.pack(fill='x', pady=(0, 10))

    ttk.Label(source_group, text="Specific TLD (optional, overrides Pages)").pack(fill='x', pady=(0,5))
    single_tld_entry = ttk.Entry(source_group, bootstyle="dark")
    single_tld_entry.pack(fill='x')

    # Advanced Group
    adv_group = ttk.Labelframe(sidebar, text="Advanced", padding=15)
    adv_group.pack(fill='x', pady=(10, 5))
    var_use_tor = tk.IntVar()
    ttk.Checkbutton(adv_group, text="Use Tor for Anonymity", variable=var_use_tor).pack(fill='x', pady=5)
    var_auto = tk.IntVar(value=1) # Set to 1 to enable by default
    ttk.Checkbutton(adv_group, text="Attempt to Auto-Solve Captchas", variable=var_auto).pack(fill='x', pady=(5,10))
    ttk.Label(adv_group, text="HTTP Proxy (optional, e.g. http://ip:port)").pack(fill='x', pady=(5,5))
    proxy_entry = ttk.Entry(adv_group, bootstyle="dark")
    proxy_entry.pack(fill='x')

    # --- Output & Action Group ---
    ttk.Separator(sidebar, bootstyle="secondary").pack(fill="x", pady=10, anchor="s")

    out_group = ttk.Frame(sidebar)
    out_group.pack(fill='x', anchor='s')
    ttk.Label(out_group, text="Number of Domains to Create (optional)").pack(fill='x', pady=(0,5))
    num_entry = ttk.Entry(out_group, bootstyle="dark")
    num_entry.pack(fill='x', pady=(0, 10))

    ttk.Label(out_group, text="Output File Name").pack(fill='x', pady=(0,5))
    outfile_entry = ttk.Entry(out_group, bootstyle="dark")
    outfile_entry.insert(0, "domainlist.txt")
    outfile_entry.pack(fill='x', pady=(0, 10))

    ttk.Label(out_group, text="Webhook URL (optional)").pack(fill='x', pady=(0,5))
    webhook_entry = ttk.Entry(out_group, bootstyle="dark")
    webhook_entry.pack(fill='x', pady=(0, 10))

    # Start button
    start_btn = ttk.Button(
        sidebar,
        text="🚀  Start Process",
        command=lambda: threading.Thread(target=init_flow, daemon=True).start(),
        style='large.success.TButton' # Use the custom style
    )
    start_btn.pack(fill="x", ipady=12, pady=(15, 10), anchor="s")

    # --- Credit in corner ---
    credit_frame = ttk.Frame(sidebar)
    credit_frame.pack(fill='x', anchor='s', pady=(0, 10))
    ttk.Label(credit_frame, text="Original by Cbass92", font=("Segoe UI Variable", 8), bootstyle="secondary").pack(side="left", padx=5)


    # ─── Output (ScrolledText) ──────────────────────────────────────────────────────
    log_widget = ScrolledText(output_frame, bg="#1e1e1e", fg="#00de7a", relief="flat",
                              insertbackground="white", font=("Consolas", 11), wrap="word",
                              bd=0, highlightthickness=0, selectbackground="#0078D7")
    log_widget.pack(fill="both", expand=True)
    log_widget.configure(state="disabled")

    # ─── Quit handling ───────────────────────────────────────────────────────────────
    def on_closing():
        log("[INFO] Shutting down...")
        stop_tor()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_closing)

    # Initial log message
    log(text2art("domain93"))
    log("Fork of Domain92 made with ❤️ by LexLeethor & Polaroid.Camera")
    root.mainloop()

if __name__ == "__main__":
    main()
