import os
import sys
import time
import threading
import subprocess
import platform
from io import BytesIO
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
from tkinter import filedialog
from tkinter.scrolledtext import ScrolledText
from ttkbootstrap import Style
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

# ─── Domain92 logic (mostly unchanged, just reading from GUI controls) ───────────

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
    log(f"[INFO] Using Tesseract at: {tess_path}")
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
        change_identity: If True and using Tor, change Tor identity before creating account
    """
    if change_identity and args.use_tor:
        log("[INFO] Changing Tor identity before creating new account...")
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                time.sleep(controller.get_newnym_wait())
                log("[INFO] Tor identity changed.")
        except Exception as e:
            log(f"[ERROR] Changing Tor identity: {e}")
    
    while True:
        try:
            log("[INFO] Fetching captcha...")
            image = getcaptcha()
            if args.auto:
                captcha = solve(image)
                log(f"[INFO] Captcha solved: {captcha}")
            else:
                log("[INFO] Showing captcha window...")
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
            sys.exit(0)
        except Exception as e:
            log(f"[ERROR] While creating account: {e}")
            # Don't change Tor identity here, just retry with same identity
            time.sleep(5)  # Short delay before retry
            continue

def createdomain():
    while True:
        try:
            # Initialize webhook variables
            hookbool = bool(args.webhook)
            webhook = args.webhook if hookbool else ""
            
            image = getcaptcha()
            if args.auto:
                capcha = solve(image)
                log("captcha solved")
            else:
                log("showing captcha")
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
                
            # Use the provided IP or default to 172.93.102.156
            ip_address = args.ip if hasattr(args, 'ip') and args.ip else "172.93.102.156"
            client.create_subdomain(capcha, args.type, subdomainy, random_domain_id, ip_address)
            
            tld = args.single_tld or domainnames[domainlist.index(random_domain_id)]
            domain_url = f"http://{subdomainy}.{tld}"
            
            log("domain created")
            log(f"link: {domain_url}")
            
            # Save to output file
            with open(args.outfile, "a") as domainsdb:
                domainsdb.write(f"\n{domain_url}")
            
            # Notify webhook if configured
            if hookbool:
                log("notifying webhook")
                try:
                    req.post(
                        webhook,
                        json={
                            "content": f"Domain created:\n{domain_url}\nIP: {ip_address}"
                        },
                        timeout=10
                    )
                    log("webhook notified")
                except Exception as e:
                    log(f"Failed to notify webhook: {e}")
        except KeyboardInterrupt:
            # quit
            sys.exit()
        except Exception as e:
            log("Got error while creating domain: " + repr(e))
            continue
        else:
            break

def createlinks(number):
    for i in range(number):
        # Only change Tor identity when starting a new account (every 5 domains)
        if i % 5 == 0:
            if args.use_tor:
                log("[INFO] Starting new account batch - changing Tor identity...")
                try:
                    with Controller.from_port(port=9051) as controller:
                        controller.authenticate()
                        controller.signal(Signal.NEWNYM)
                        time.sleep(controller.get_newnym_wait())
                        log("[INFO] Tor identity changed successfully")
                except Exception as e:
                    log(f"[ERROR] Failed to change Tor identity: {e}")
                    log("[WARNING] Continuing with current Tor circuit")
            
            # Create a new account with the new identity
            login(change_identity=False)
        
        # Create a domain with the current account
        createdomain()

def init_flow():
    """
    Main entry point that mimics your CLI init(), but reads from GUI controls instead.
    """
    global non_random_domain_id

    # Read GUI controls:
    args.ip = ip_entry.get().strip()
    args.number = int(num_entry.get()) if num_entry.get().strip().isdigit() else None
    args.webhook = webhook_entry.get().strip()
    args.proxy = proxy_entry.get().strip() or None
    args.use_tor = bool(var_use_tor.get())
    args.silent = False  # In GUI, we always show log.
    args.outfile = outfile_entry.get().strip() or "domainlist.txt"
    args.type = type_var.get().strip() or "A"
    args.pages = pages_entry.get().strip() or "10"
    args.subdomains = subdomains_entry.get().strip() or "random"
    args.auto = bool(var_auto.get())
    args.single_tld = single_tld_entry.get().strip()

    # Set up proxies/Tor for the freedns client:
    if args.use_tor:
        start_tor()
        client.session.proxies.update({
            "http": "socks5h://127.0.0.1:9050",
            "https": "socks5h://127.0.0.1:9050",
        })
        log("[INFO] Using Tor proxy for HTTP requests.")
    elif args.proxy:
        client.session.proxies.update({"http": args.proxy, "https": args.proxy})
        log(f"[INFO] Using HTTP proxy: {args.proxy}")

    # Set default IP if not provided
    if not args.ip:
        args.ip = "172.93.102.156"
        log(f"[INFO] No IP provided. Using default IP: {args.ip}")

    # Determine pages to scrape:
    if not args.pages:
        args.pages = "10"

    # Handle single_tld or get all domains
    non_random_domain_id = None
    if args.single_tld:
        try:
            non_random_domain_id = find_domain_id(args.single_tld)
            log(f"[INFO] Using single TLD ID: {non_random_domain_id}")
        except Exception as e:
            log(f"[ERROR] Could not find domain ID for TLD '{args.single_tld}': {e}")
            return
    else:
        try:
            log("[INFO] Fetching domain list...")
            getdomains(args.pages)
            log(f"[INFO] Total domains fetched: {len(domainlist)}")
        except Exception as e:
            log(f"[ERROR] getdomains() failed: {e}")
            return

    # If number was provided, create that many; else do one full batch of five
    if args.number:
        createlinks(args.number)
    else:
        login()
        for _ in range(5):
            createdomain()

    if args.use_tor:
        stop_tor()

    log("[INFO] All done.")

# ─── Build the Tkinter UI ────────────────────────────────────────────────────────

root_style = Style("superhero")
root = root_style.master
root.title("🚀 Domain92 GUI")
root.state("zoomed")    # On Windows, this will open the window maximized.
root.resizable(True, True)

# Sidebar frame
sidebar = tk.Frame(root, width=300, bg="#2b2b2b", padx=10, pady=10)
sidebar.pack(side="left", fill="y")

# Main output frame
output_frame = tk.Frame(root, padx=10, pady=10)
output_frame.pack(side="right", fill="both", expand=True)

# ─── Sidebar widgets ────────────────────────────────────────────────────────────

tk.Label(sidebar, text="Domain92 GUI", fg="white", bg="#2b2b2b", font=("Segoe UI", 18, "bold")).pack(pady=(0, 15))

# IP
tk.Label(sidebar, text="IP Address:", fg="white", bg="#2b2b2b").pack(anchor="w")
ip_entry = tk.Entry(sidebar)
ip_entry.pack(fill="x", pady=(0, 10))

# Number of links
tk.Label(sidebar, text="Number of links (optional):", fg="white", bg="#2b2b2b").pack(anchor="w")
num_entry = tk.Entry(sidebar)
num_entry.pack(fill="x", pady=(0, 10))

# Pages to scrape
tk.Label(sidebar, text="Pages to scrape (e.g. 1-10):", fg="white", bg="#2b2b2b").pack(anchor="w")
pages_entry = tk.Entry(sidebar)
pages_entry.insert(0, "10")
pages_entry.pack(fill="x", pady=(0, 10))

# Subdomains
tk.Label(sidebar, text="Subdomains (comma or 'random'):", fg="white", bg="#2b2b2b").pack(anchor="w")
subdomains_entry = tk.Entry(sidebar)
subdomains_entry.insert(0, "random")
subdomains_entry.pack(fill="x", pady=(0, 10))

# Single TLD (optional)
tk.Label(sidebar, text="Single TLD (optional):", fg="white", bg="#2b2b2b").pack(anchor="w")
single_tld_entry = tk.Entry(sidebar)
single_tld_entry.pack(fill="x", pady=(0, 10))

# Record type
tk.Label(sidebar, text="Record type (default A):", fg="white", bg="#2b2b2b").pack(anchor="w")
type_var = tk.StringVar(value="A")
type_menu = tk.OptionMenu(sidebar, type_var, "A", "AAAA", "CNAME", "TXT")
type_menu.configure(bg="#3b3b3b", fg="white")
type_menu.pack(fill="x", pady=(0, 10))

# Webhook
tk.Label(sidebar, text="Webhook URL (optional):", fg="white", bg="#2b2b2b").pack(anchor="w")
webhook_entry = tk.Entry(sidebar)
webhook_entry.pack(fill="x", pady=(0, 10))

# Proxy
tk.Label(sidebar, text="HTTP Proxy (optional):", fg="white", bg="#2b2b2b").pack(anchor="w")
proxy_entry = tk.Entry(sidebar)
proxy_entry.pack(fill="x", pady=(0, 10))

# Use Tor?
var_use_tor = tk.IntVar()
tk.Checkbutton(sidebar, text="Use Tor", variable=var_use_tor, fg="white", bg="#2b2b2b", selectcolor="#2b2b2b").pack(anchor="w", pady=(0, 10))

# Auto solve captcha?
var_auto = tk.IntVar()
tk.Checkbutton(sidebar, text="Auto‐solve Captcha", variable=var_auto, fg="white", bg="#2b2b2b", selectcolor="#2b2b2b").pack(anchor="w", pady=(0, 10))
# Start button
start_btn = tk.Button(sidebar, text="🚀 Start", command=lambda: threading.Thread(target=init_flow, daemon=True).start(),
                      bg="#4caf50", fg="white", font=("Segoe UI", 12, "bold"))
start_btn.pack(fill="x", pady=(0, 20))

# Output filename
tk.Label(sidebar, text="Output file:", fg="white", bg="#2b2b2b").pack(anchor="w")
outfile_entry = tk.Entry(sidebar)
outfile_entry.insert(0, "domainlist.txt")
outfile_entry.pack(fill="x", pady=(0, 20))


# ─── Output (ScrolledText) ──────────────────────────────────────────────────────

log_widget = ScrolledText(output_frame, bg="#1e1e1e", fg="#00ff99", insertbackground="white",
                          font=("Consolas", 10), wrap="word")
log_widget.pack(fill="both", expand=True)
log_widget.configure(state="disabled")

# ─── Quit handling ───────────────────────────────────────────────────────────────

def on_closing():
    stop_tor()
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)

# Kick off initial ASCII art if desired
log("Starting Domain92 GUI...")
log("Made with ❤️ by Cbass92")

root.mainloop()
