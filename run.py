# ── Colour helpers ────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BLUE   = "\033[94m"
RESET  = "\033[0m"

def ok(msg):   print(f"{GREEN}[OK]  {msg}{RESET}")
def warn(msg): print(f"{YELLOW}[WARN]  {msg}{RESET}")
def err(msg):  print(f"{RED}[ERROR]  {msg}{RESET}")
def info(msg): print(f"{BLUE}[INFO]  {msg}{RESET}")