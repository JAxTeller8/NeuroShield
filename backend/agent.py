import os
import sys
import time
import random
import requests
import psutil
import csv
import json
import logging
import re
import ctypes
import socket

# ----------------------------------------------------
# Modular Agent Configuration
# ----------------------------------------------------
CONFIG = {
    # Flask backend API address. Can be a local address or a remote cloud IP/domain.
    "BACKEND_URL": os.getenv("NEUROSHIELD_BACKEND_URL", "http://127.0.0.1:5000"),
    
    # Path to store agent logs
    "LOG_FILE_PATH": os.getenv("NEUROSHIELD_LOG_PATH", r"C:\ProgramData\NeuroShield\agent.log"),
    
    # Monitoring interval in seconds between process scans
    "MONITOR_INTERVAL": float(os.getenv("NEUROSHIELD_MONITOR_INTERVAL", "2.0")),
    
    # Threat response: True to kill detected threats immediately, False to log only
    "AUTO_TERMINATE": os.getenv("NEUROSHIELD_AUTO_TERMINATE", "True").lower() == "true",
}

# ----------------------------------------------------
# Terminal Interaction Colors (ANSI Escape Sequences)
# ----------------------------------------------------
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
MAGENTA = '\033[95m'
BOLD = '\033[1m'
RESET = '\033[0m'

# ----------------------------------------------------
# System Process Whitelist (Safety Shield)
# ----------------------------------------------------
SYSTEM_WHITELIST = {
    "explorer.exe", "python.exe", "pythonw.exe", "python3.exe", "python3.9.exe",
    "cmd.exe", "powershell.exe", "conhost.exe", "svchost.exe", "lsass.exe",
    "services.exe", "wininit.exe", "csrss.exe", "smss.exe", "spoolsv.exe",
    "taskhostw.exe", "winlogon.exe", "system", "idle", "searchhost.exe",
    "startmenuexperiencehost.exe", "textinputhost.exe", "taskmgr.exe",
    "securityhealthservice.exe", "brave.exe", "chrome.exe", "msedge.exe"
}

# Dynamically add the current running Python executable to the whitelist
try:
    SYSTEM_WHITELIST.add(os.path.basename(sys.executable).lower())
except Exception:
    pass

# ----------------------------------------------------
# Logging Configuration with ANSI Escape Sequence Stripper
# ----------------------------------------------------
class AnsiStrippingFormatter(logging.Formatter):
    """
    Strips ANSI color codes from log records before writing to files.
    """
    ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')
    
    def format(self, record):
        formatted = super().format(record)
        return self.ANSI_ESCAPE.sub('', formatted)

def setup_logging():
    log_dir = os.path.dirname(CONFIG["LOG_FILE_PATH"])
    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception:
        # Fallback to local directory log if ProgramData is unavailable
        fallback_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
        os.makedirs(fallback_dir, exist_ok=True)
        CONFIG["LOG_FILE_PATH"] = os.path.join(fallback_dir, "agent.log")

    logger = logging.getLogger("NeuroShieldAgent")
    logger.setLevel(logging.INFO)
    
    if logger.handlers:
        return logger

    # File Handler (ANSI Stripped for clean text files)
    try:
        file_handler = logging.FileHandler(CONFIG["LOG_FILE_PATH"], encoding='utf-8')
        file_formatter = AnsiStrippingFormatter(
            '[%(asctime)s] [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    except Exception as e:
        sys.stderr.write(f"Warning: Failed to setup file logger: {e}\n")

    # Console Handler (Keeps Colors, interactive terminal sessions only)
    if sys.stdout and sys.stdout.isatty():
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter('%(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    return logger

logger = setup_logging()

# ----------------------------------------------------
# Windows Service Imports & Setup
# ----------------------------------------------------
try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    import socket
    PYWIN32_AVAILABLE = True
except ImportError:
    PYWIN32_AVAILABLE = False

# Helper sleep function that respects Service Stop Events
def sleep_or_stop(seconds, service=None):
    if service and PYWIN32_AVAILABLE:
        result = win32event.WaitForSingleObject(service.hWaitStop, int(seconds * 1000))
        if result == win32event.WAIT_OBJECT_0:
            return True
    else:
        time.sleep(seconds)
    return False

# ----------------------------------------------------
# Programmatic Console Hiding (ctypes)
# ----------------------------------------------------
def hide_console():
    """
    Hides the console window if running on Windows and not launched in a terminal.
    """
    try:
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            # 0 = SW_HIDE
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass

# ----------------------------------------------------
# Pure-Python Lightweight Tokenizer
# ----------------------------------------------------
class SimpleTokenizer:
    """
    A lightweight, pure-Python Keras-compatible Tokenizer.
    Loads 'word_index' from a Keras tokenizer JSON serialization and
    performs texts_to_sequences mapping without importing TensorFlow.
    """
    def __init__(self, tokenizer_json_path):
        if not os.path.exists(tokenizer_json_path):
            raise FileNotFoundError(f"Tokenizer cache not found at: {tokenizer_json_path}")
            
        with open(tokenizer_json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            
        config = data.get('config', {})
        self.oov_token = config.get('oov_token', '<OOV>')
        self.lower = config.get('lower', True)
        
        word_index_raw = config.get('word_index')
        if isinstance(word_index_raw, str):
            self.word_index = json.loads(word_index_raw)
        elif isinstance(word_index_raw, dict):
            self.word_index = word_index_raw
        else:
            self.word_index = {}
            
    def texts_to_sequences(self, texts):
        sequences = []
        for text in texts:
            if self.lower:
                text = text.lower()
            words = text.split()
            seq = []
            for word in words:
                idx = self.word_index.get(word, self.word_index.get(self.oov_token, 1))
                seq.append(idx)
            sequences.append(seq)
        return sequences

def get_tokenizer():
    """
    Loads Tokenizer from JSON cache to reduce startup delay.
    If cache is missing, it rebuilds it from the CSV dataset manually without TensorFlow.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    tokenizer_path = os.path.join(base_dir, 'ai_engine', 'tokenizer.json')
    
    if os.path.exists(tokenizer_path):
        logger.info(f"{CYAN}[+] Loading Tokenizer from fast cache...{RESET}")
        return SimpleTokenizer(tokenizer_path)
    else:
        logger.warning(f"{YELLOW}[*] Tokenizer cache not found. Rebuilding from CSV dataset (pure Python execution)...{RESET}")
        csv_path = os.path.join(base_dir, 'ai_engine', 'dynamic_api_call_sequence_per_malware_100_0_306.csv')
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"[-] Error: Dataset CSV file not found at: {csv_path}")
            
        # Fit tokenizer manually based on API call frequency
        word_counts = {}
        with open(csv_path, 'r', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)
            t_indices = [i for i, col in enumerate(header) if col.startswith('t_')]
            
            for row in reader:
                if not row:
                    continue
                for idx in t_indices:
                    if idx < len(row):
                        val = row[idx].strip().lower()
                        if val:
                            word_counts[val] = word_counts.get(val, 0) + 1
                            
        # Sort words by frequency to match Keras numbering scheme
        sorted_words = sorted(word_counts.items(), key=lambda x: x[1], reverse=True)
        
        # Word index starts from 2 (1 is reserved for OOV)
        word_index = {"<OOV>": 1}
        for idx, (word, _) in enumerate(sorted_words):
            word_index[word] = idx + 2
            
        # Write tokenizer cache
        tokenizer_data = {
            "class_name": "Tokenizer",
            "config": {
                "num_words": None,
                "filters": "",
                "lower": True,
                "split": " ",
                "char_level": False,
                "oov_token": "<OOV>",
                "word_index": json.dumps(word_index)
            }
        }
        
        os.makedirs(os.path.dirname(tokenizer_path), exist_ok=True)
        with open(tokenizer_path, 'w', encoding='utf-8') as f:
            json.dump(tokenizer_data, f)
            
        logger.info(f"{GREEN}[+] Tokenizer cache saved successfully for faster startup.{RESET}")
        return SimpleTokenizer(tokenizer_path)

# ----------------------------------------------------
# Load Telemetry Simulation Samples
# ----------------------------------------------------
def load_simulation_samples():
    """
    Loads authentic sequence rows from dataset to power process behavior simulation (pure Python).
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(base_dir, 'ai_engine', 'dynamic_api_call_sequence_per_malware_100_0_306.csv')
    
    logger.info(f"{CYAN}[*] Loading telemetry simulation samples from dataset...{RESET}")
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"[-] Dataset CSV file not found at: {csv_path}")
        
    malicious_samples = []
    healthy_samples = []
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.reader(f)
        header = next(reader)
        
        t_indices = [i for i, col in enumerate(header) if col.startswith('t_')]
        try:
            malware_idx = header.index('malware')
        except ValueError:
            malware_idx = -1
            
        for row in reader:
            if not row:
                continue
            seq = [row[i] for i in t_indices if i < len(row)]
            
            is_malicious = False
            if malware_idx != -1 and malware_idx < len(row):
                is_malicious = (row[malware_idx].strip() == '1')
                
            if is_malicious:
                malicious_samples.append(seq)
            else:
                healthy_samples.append(seq)
                
    logger.info(f"{GREEN}[+] Loaded {len(malicious_samples)} malicious ransomware samples and {len(healthy_samples)} healthy samples for behavioral simulation.{RESET}")
    return malicious_samples, healthy_samples

# ----------------------------------------------------
# Main Monitoring Agent Loop
# ----------------------------------------------------
def run_agent(service=None):
    # 1. Print Banner (Only on interactive consoles)
    if sys.stdout and sys.stdout.isatty():
        print(f"\n{BOLD}{MAGENTA}===================================================={RESET}")
        print(f"{BOLD}{MAGENTA}     🛡️  NeuroShield 🛡️{RESET}")
        print(f"{BOLD}{MAGENTA}===================================================={RESET}\n")
    
    logger.info("[+] NeuroShield Initializing...")
    
    # 2. Check Backend Connection
    backend_url = CONFIG["BACKEND_URL"]
    logger.info(f"[+] Checking connection to Flask Backend at {backend_url}...")
    try:
        res = requests.get(f"{backend_url}/api/status", timeout=5)
        if res.status_code == 200:
            logger.info(f"{GREEN}[+] Connection established. Flask server online and Model loaded successfully.{RESET}")
        else:
            logger.warning(f"{YELLOW}[!] Connected to server, but there is an issue with the model state: {res.json()}{RESET}")
    except requests.exceptions.ConnectionError:
        logger.error(f"{RED}[❌] Critical Error: Cannot connect to Flask Backend at {backend_url}{RESET}")
        logger.error(f"{RED}[*] Please ensure Flask server is running first (python app.py){RESET}")
        if service is None:
            sys.exit(1)

    # 3. Load Tokenizer & Samples
    try:
        tokenizer = get_tokenizer()
        mal_samples, hlth_samples = load_simulation_samples()
    except Exception as e:
        logger.error(f"{RED}[❌] Failed to initialize agent: {e}{RESET}")
        if service is None:
            sys.exit(1)
        return

    # 4. Enumerate Existing Processes
    logger.info(f"{CYAN}[*] Enumerating active system processes for real-time monitoring...{RESET}")
    monitored_pids = set(p.pid for p in psutil.process_iter())
    logger.info(f"{GREEN}[+] Logged {len(monitored_pids)} active processes. Core Agent monitoring is active.{RESET}")
    logger.info(f"{YELLOW}[*] Tip: To test threat detection and automated termination, spawn any new process or run a renamed executable containing 'ransom' (e.g., ransom_test.exe).{RESET}")

    # 5. Monitoring Loop
    while service is None or service.is_running:
        try:
            for proc in psutil.process_iter(['pid', 'name']):
                if service and not service.is_running:
                    break
                    
                try:
                    pid = proc.info['pid']
                    name = proc.info['name']
                    
                    # Skip System Protected PIDs (0 and 4)
                    if pid == 0 or pid == 4:
                        continue
                        
                    if pid not in monitored_pids:
                        monitored_pids.add(pid)
                        
                        # Apply Whitelist Check
                        if name and name.lower() in SYSTEM_WHITELIST:
                            logger.info(f"{CYAN}[*] Process {name} (PID: {pid}) is whitelisted. Skipping.{RESET}")
                            continue
                            
                        # Log Telemetry Analysis
                        logger.info(f"[🔄] Analyzing Telemetry for {name} (PID: {pid})...")
                        
                        # Simulate Process Behavior
                        is_simulated_malicious = any(k in name.lower() for k in ["ransom", "crypt", "lock", "malware", "test_malicious"])
                        
                        if is_simulated_malicious:
                            logger.warning(f"{YELLOW}[!] Process {name} matches threat keywords. Simulating ransomware behavior...{RESET}")
                            if mal_samples:
                                raw_api_sequence = random.choice(mal_samples)
                            else:
                                raw_api_sequence = ["LdrLoadDll"] * 100
                        else:
                            if hlth_samples:
                                raw_api_sequence = random.choice(hlth_samples)
                            else:
                                raw_api_sequence = ["RegOpenKeyEx"] * 100
                            
                        # Encode sequence with Tokenizer
                        sequence_text = ' '.join(str(val) for val in raw_api_sequence)
                        tokenized_sequence = tokenizer.texts_to_sequences([sequence_text])[0]
                        
                        # Submit POST request to model endpoint with metadata
                        payload = {
                            "sequence": tokenized_sequence,
                            "process_name": name,
                            "pid": pid,
                            "hostname": socket.gethostname()
                        }
                        api_res = requests.post(f"{backend_url}/api/analyze", json=payload, timeout=5)
                        
                        if api_res.status_code == 200:
                            result = api_res.json()
                            is_malicious = result.get("malicious", False)
                            confidence = result.get("confidence", 0.0)
                            risk_pct = result.get("risk_percentage", 0.0)
                            
                            if is_malicious:
                                # 🚨 AGGRESSIVE RED THREAT WARNING BANNER
                                logger.error(f"{RED}{BOLD}🚨🚨🚨 NEUROSHIELD THREAT DETECTION 🚨🚨🚨{RESET}")
                                logger.error(f"{RED}{BOLD}========================================{RESET}")
                                logger.error(f"{RED}{BOLD}⚠️ CRITICAL RANSOMWARE BEHAVIOR DETECTED!{RESET}")
                                logger.error(f"{RED}{BOLD}💥 Process Name : {name}{RESET}")
                                logger.error(f"{RED}{BOLD}🆔 Process ID   : {pid}{RESET}")
                                logger.error(f"{RED}{BOLD}🔥 Risk Factor  : {risk_pct:.2f}%{RESET}")
                                
                                if CONFIG["AUTO_TERMINATE"]:
                                    logger.error(f"{RED}{BOLD}💥 ACTION TAKEN : ENFORCING IMMEDIATE TERMINATION!{RESET}")
                                    logger.error(f"{RED}{BOLD}========================================{RESET}")
                                    
                                    # Terminate Process Immediately
                                    try:
                                        p_to_kill = psutil.Process(pid)
                                        p_to_kill.kill()
                                        logger.error(f"{RED}[❌] {GREEN}{BOLD}Process {pid} terminated successfully! System secured.{RESET}")
                                    except Exception as kill_err:
                                        logger.error(f"{RED}[❌] Failed to terminate process {name}: {kill_err}{RESET}")
                                else:
                                    logger.error(f"{YELLOW}[⚠️] ACTION TAKEN : AUTO-TERMINATION DISABLED. REPORT ONLY.{RESET}")
                                    logger.error(f"{RED}{BOLD}========================================{RESET}")
                            else:
                                logger.info(f"{GREEN}[✓] Process {name} (PID: {pid}) analyzed. Behavior is normal (Safety score: {100 - (confidence * 100):.2f}%).{RESET}")
                        else:
                            logger.error(f"{RED}[!] Failed to analyze process: Server returned status {api_res.status_code}{RESET}")
                            
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
            if service and not service.is_running:
                break
                
            # Respect monitor interval or stop signal
            if sleep_or_stop(CONFIG["MONITOR_INTERVAL"], service):
                break
                
        except Exception as e:
            logger.error(f"{RED}[-] Error in core EDR loop: {e}{RESET}")
            if sleep_or_stop(5.0, service):
                break
                
    logger.info("[*] NeuroShield stopped. Monitoring suspended.")

# ----------------------------------------------------
# Windows Service Class Wrapper
# ----------------------------------------------------
if PYWIN32_AVAILABLE:
    class NeuroShieldAgentService(win32serviceutil.ServiceFramework):
        _svc_name_ = "NeuroShield"
        _svc_display_name_ = "NeuroShield"
        _svc_description_ = "NeuroShield"
        
        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            socket.setdefaulttimeout(60)
            self.is_running = True

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.hWaitStop)
            self.is_running = False

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            run_agent(self)

# ----------------------------------------------------
# Script Entrypoint
# ----------------------------------------------------
if __name__ == "__main__":
    # Check if we are administering service via cmd line
    if len(sys.argv) > 1 and sys.argv[1] in ["install", "remove", "start", "stop", "restart", "status", "debug"]:
        if PYWIN32_AVAILABLE:
            win32serviceutil.HandleCommandLine(NeuroShieldAgentService)
        else:
            sys.stderr.write("[-] Error: 'pywin32' is not installed or available on this system.\n")
            sys.stderr.write("[*] Cannot install or manage as a Windows Service. Running interactive agent...\n")
            run_agent()
    else:
        # If not interactive and no explicitly passed debug flag, run silently
        is_interactive = sys.stdout and sys.stdout.isatty()
        if not is_interactive and "--no-hide" not in sys.argv:
            hide_console()
            
        try:
            run_agent()
        except KeyboardInterrupt:
            logger.info(f"\n{YELLOW}[*] NeuroShield stopped by user. System monitoring suspended.{RESET}")
