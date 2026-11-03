from __future__ import annotations

import base64
import json
import os
import random
import re
import subprocess
import sys
import tempfile
import time
import uuid
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterator, Sequence

try:
    from curl_cffi import requests as curl_requests
    HAS_CURL_CFFI = True
except ImportError:
    curl_requests = None
    HAS_CURL_CFFI = False

for stream in (sys.stdout, sys.stderr):
    try:
        stream.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, OSError):
        pass

ROOT = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
GAMES_FILE = ROOT.parent / "data" / "games.json"
STATE_FILE = ROOT / "science_state.json"
PROXIES_FILE = ROOT / "proxies.txt"
DATA_PROXIES_FILE = ROOT.parent / "data" / "proxies.txt"

ME_URL = "https://discord.com/api/v9/users/@me?with_analytics_token=true"
SCIENCE_URL = "https://discord.com/api/v9/science"
PROPERTIES_URL = "https://cordapi.dolfi.es/api/v2/properties/windows"
GAMES_CDN_URL = "https://cdn.discordapp.com/detectables/games.json"

BATCH_SIZE = 50
BATCH_DELAY = 1
AUTH_MAX_AGE = 12 * 3600
DEBUG = False

CLIENT_VERSION = "1.0.9253"
NATIVE_BUILD_NUMBER = 88414
OS_VERSION = "10.0.26200"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) discord/1.0.9253 Chrome/148.0.7778.280 "
    "Electron/42.7.1 Safari/537.36"
)


def fetch_build_number(fallback: int = 657850) -> int:
    try:
        if HAS_CURL_CFFI:
            resp = curl_requests.get("https://discord.com/app", impersonate="chrome131", timeout=8)
            text = resp.text
        else:
            req = urllib.request.Request("https://discord.com/app", headers={"user-agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=8) as r:
                text = r.read().decode("utf-8", errors="ignore")

        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', text)
        for s in reversed(scripts):
            if not s.endswith(".js"):
                continue
            url = f"https://discord.com{s}" if s.startswith("/") else s
            if HAS_CURL_CFFI:
                js_text = curl_requests.get(url, impersonate="chrome131", timeout=8).text
            else:
                req = urllib.request.Request(url, headers={"user-agent": USER_AGENT})
                with urllib.request.urlopen(req, timeout=8) as r:
                    js_text = r.read().decode("utf-8", errors="ignore")

            m = re.search(r'buildNumber["\s:]+(\d{5,7})', js_text)
            if m:
                return int(m.group(1))
    except Exception:
        pass
    return fallback


CLIENT_BUILD_NUMBER = fetch_build_number()


def sanitize_token(token: str) -> str:
    token = token.strip().strip('"').strip("'")
    for pfx in ("Bot ", "Bearer ", "bot ", "bearer "):
        if token.startswith(pfx):
            token = token[len(pfx):].strip()
    return token


def sanitize_cookie(raw: str) -> str:
    raw = raw.strip().strip('"').strip("'")
    if not raw:
        return ""
    if raw.lower().startswith("cookie:"):
        raw = raw[7:].strip()
    match = re.search(r'cf_clearance=([a-zA-Z0-9_\.\-]+)', raw)
    if match:
        return f"cf_clearance={match.group(1)}"
    if "=" not in raw:
        return f"cf_clearance={raw}"
    return raw


def load_proxies() -> list[str]:
    for p in (PROXIES_FILE, DATA_PROXIES_FILE):
        if p.exists():
            lines = [l.strip() for l in p.read_text(encoding="utf-8").splitlines() if l.strip() and not l.startswith("#")]
            if lines:
                return lines
    return []


def _user_id_from_token(token: str) -> str:
    try:
        first = token.split(".", 1)[0]
        pad = "=" * (-len(first) % 4)
        return base64.b64decode(first + pad).decode("utf-8")
    except Exception:
        return ""


_FINGERPRINT_PS1 = r'''
param(
  [int]$ProcessId = 0,
  [string]$Path,
  [Parameter(Mandatory = $true)][string]$UserId
)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class CertPubKeyHash {
  const uint X509_ASN_ENCODING = 0x00000001;
  const uint PKCS_7_ASN_ENCODING = 0x00010000;
  const uint CALG_SHA_256 = 0x0000800C;

  [StructLayout(LayoutKind.Sequential)] struct Blob { public uint cbData; public IntPtr pbData; }
  [StructLayout(LayoutKind.Sequential)] struct AlgId { public IntPtr pszObjId; public Blob Parameters; }
  [StructLayout(LayoutKind.Sequential)] struct BitBlob { public uint cbData; public IntPtr pbData; public uint cUnusedBits; }
  [StructLayout(LayoutKind.Sequential)] struct PubKeyInfo { public AlgId Algorithm; public BitBlob PublicKey; }
  [StructLayout(LayoutKind.Sequential)] struct FileTime { public uint Low; public uint High; }
  [StructLayout(LayoutKind.Sequential)]
  struct CertInfo {
    public uint Version; public Blob SerialNumber; public AlgId SignatureAlgorithm; public Blob Issuer;
    public FileTime NotBefore; public FileTime NotAfter; public Blob Subject;
    public PubKeyInfo SubjectPublicKeyInfo; public BitBlob IssuerUniqueId; public BitBlob SubjectUniqueId;
    public uint ExtensionCount; public IntPtr Extensions;
  }
  [StructLayout(LayoutKind.Sequential)]
  struct CertContext {
    public uint EncodingType; public IntPtr Encoded; public uint EncodedSize;
    public IntPtr CertInfo; public IntPtr Store;
  }

  [DllImport("crypt32.dll", SetLastError = true)]
  static extern bool CryptHashPublicKeyInfo(
    IntPtr provider, uint algid, uint flags, uint encoding, ref PubKeyInfo info, byte[] hash, ref uint hashSize);

  public static byte[] Hash(IntPtr certContext) {
    var ctx = Marshal.PtrToStructure<CertContext>(certContext);
    var info = Marshal.PtrToStructure<CertInfo>(ctx.CertInfo);
    var hash = new byte[32];
    uint hashSize = 32;
    if (!CryptHashPublicKeyInfo(IntPtr.Zero, CALG_SHA_256, 0, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, ref info.SubjectPublicKeyInfo, hash, ref hashSize) || hashSize != 32)
      throw new InvalidOperationException("CryptHashPublicKeyInfo failed");
    return hash;
  }
}
"@

if (!$Path) {
  if (!$ProcessId) { throw "Pass -Path <exe> or -ProcessId <pid>." }
  $Path = (Get-Process -Id $ProcessId).Path
}
if (!$Path) { throw "Could not resolve executable path." }

$fs = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
try {
  $fileSize = [UInt64]$fs.Length
  $readSize = [int][Math]::Min($fs.Length, 0x10000)
  $buf = [byte[]]::new($readSize)
  $read = $fs.Read($buf, 0, $readSize)
  if ($read -lt 0x40) { throw "File prefix is too small." }
  if ($read -ne $readSize) { [Array]::Resize([ref]$buf, $read) }
} finally {
  $fs.Dispose()
}

if ([BitConverter]::ToUInt16($buf, 0) -ne 0x5A4D) { throw "Not an MZ executable." }
$pe = [BitConverter]::ToInt32($buf, 0x3C)
if ($pe -lt 0 -or [BitConverter]::ToUInt32($buf, $pe) -ne 0x4550) { throw "Not a PE executable." }

$fh = $pe + 4
$sections = [BitConverter]::ToUInt16($buf, $fh + 2)
$timestamp = [BitConverter]::ToUInt32($buf, $fh + 4)
$optSize = [BitConverter]::ToUInt16($buf, $fh + 16)
$opt = $fh + 20
$isPe32Plus = [BitConverter]::ToUInt16($buf, $opt) -eq 0x20B
if (!$isPe32Plus) { throw "Discord only fingerprints PE32+." }
$sizeOfImage = [BitConverter]::ToUInt32($buf, $opt + 56)

$sectionTable = $opt + $optSize
$sha256 = [Security.Cryptography.SHA256]::Create()
$headerHash = $sha256.ComputeHash([byte[]]$buf[0..($sectionTable - 1)])
$sectionHash = $sha256.ComputeHash([byte[]]$buf[$sectionTable..($sectionTable + $sections * 40 - 1)])

$machineGuid = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Cryptography" -Name MachineGuid).MachineGuid
$machineUserHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($machineGuid + $UserId))

$sig = Get-AuthenticodeSignature -LiteralPath $Path
$signed = $sig.Status -eq "Valid" -and $sig.SignerCertificate
if ($signed) {
  $name = $sig.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
  $certHash = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($name) + [CertPubKeyHash]::Hash($sig.SignerCertificate.Handle))
} else {
  $certHash = [byte[]]::new(32)
}

$flags = 0
if ($signed) { $flags += 1 }
if ($isPe32Plus) { $flags += 2 }

$out = [byte[]](@(1, [byte]$flags) +
  [BitConverter]::GetBytes($fileSize) +
  [BitConverter]::GetBytes($timestamp) +
  [BitConverter]::GetBytes($sizeOfImage) +
  $headerHash + $machineUserHash + $sectionHash + $certHash)

$key = $sha256.ComputeHash([Text.Encoding]::UTF8.GetBytes($UserId + "https://discord.com/careers"))
for ($i = 1; $i -lt $out.Length; $i++) {
  $out[$i] = $out[$i] -bxor $key[($i - 1) -band 31]
}

[Convert]::ToBase64String($out)
'''


def generate_fingerprint(user_id: str, path: str = "", pid: int = 0) -> str:
    if os.name != "nt":
        raise RuntimeError("fingerprint generation is windows-only")
    script = Path(tempfile.gettempdir()) / f"disc_fp_{uuid.uuid4().hex}.ps1"
    script.write_text(_FINGERPRINT_PS1, encoding="utf-8")
    try:
        args = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                "-File", str(script), "-UserId", user_id]
        args += (["-ProcessId", str(pid)] if pid else ["-Path", path])
        result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    finally:
        try:
            script.unlink()
        except OSError:
            pass
    if result.returncode != 0:
        lines = (result.stderr or result.stdout or "").strip().splitlines()
        raise RuntimeError(lines[-1] if lines else "powershell failed")
    out = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not out:
        raise RuntimeError("generator produced no output")
    return out[-1]


class Logger:
    def __init__(self) -> None:
        self.DIM = "\033[38;5;239m"
        self.TIME_GRAY = "\033[38;5;244m"
        self.KEY_GRAY = "\033[38;5;243m"
        self.WHITE = "\033[38;5;254m"
        self.SUCCESS = "\033[38;5;120m"
        self.FAIL = "\033[38;5;203m"
        self.WARN = "\033[38;5;214m"
        self.INFO = "\033[38;5;75m"
        self.PURPLE = "\033[38;5;141m"
        self.PINK = "\033[38;5;213m"
        self.RESET = "\033[0m"
        import threading
        self.print_lock = threading.Lock()
        if sys.platform == "win32":
            self._enable_ansi()

    @staticmethod
    def _enable_ansi() -> None:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x0004)

    @staticmethod
    def get_time() -> str:
        return time.strftime("%H:%M:%S")

    def prefix(self, char: str, color: str) -> str:
        return f"{self.DIM}({color}{char}{self.DIM}){self.RESET}"

    def _log_status(self, char: str, char_color: str, tag: str, tag_color: str, **kwargs) -> None:
        with self.print_lock:
            time_str = f"{self.DIM}[{self.TIME_GRAY}{self.get_time()}{self.DIM}]{self.RESET}"
            pfx = self.prefix(char, char_color)
            tag_str = f"{tag_color}{tag:<6}{self.RESET}"
            sep = f"{self.DIM}»{self.RESET}"

            parts = []
            for k, v in kwargs.items():
                if k == 'error':
                    parts.append(f"{self.KEY_GRAY}{k}:{self.RESET} {self.FAIL}{v}")
                elif k == 'status':
                    status_val = "SUCCESS" if str(v) in ('204', 'SUCCESS') else str(v)
                    status_color = self.SUCCESS if status_val == 'SUCCESS' else self.FAIL
                    parts.append(f"{self.KEY_GRAY}{k}:{self.RESET} {status_color}{status_val}")
                elif k == 'pct':
                    parts.append(f"{self.DIM}[{self.INFO}{v}{self.DIM}]{self.RESET}")
                elif k in ('batch', 'games'):
                    parts.append(f"{self.KEY_GRAY}{k}:{self.RESET} {self.WHITE}{v}")
                else:
                    parts.append(f"{self.KEY_GRAY}{k}:{self.RESET} {self.WHITE}{v}")

            details = f" {self.RESET}".join(parts)
            print(f"{time_str} {pfx} {tag_str} {sep} {details}{self.RESET}", flush=True)

    def log_line(self, char: str, char_color: str, text: str) -> None:
        with self.print_lock:
            time_str = f"{self.DIM}[{self.TIME_GRAY}{self.get_time()}{self.DIM}]{self.RESET}"
            pfx = self.prefix(char, char_color)
            print(f"{time_str} {pfx} {text}{self.RESET}", flush=True)

    def inf(self, text: str) -> None:
        self.log_line('/', self.INFO, text)

    def info(self, text: str, **kwargs) -> None:
        if kwargs:
            extra = ', '.join(f"{k}= {v}" for k, v in kwargs.items())
            self.inf(f"{text} -> {extra}")
        else:
            self.inf(text)

    def success(self, text: str, **kwargs) -> None:
        if kwargs:
            extra = ', '.join(f"{k}= {v}" for k, v in kwargs.items())
            self.log_line('+', self.SUCCESS, f"{text} -> {extra}")
        else:
            self.log_line('+', self.SUCCESS, text)

    def ok(self, target: str, detail: str) -> None:
        self.log_line('+', self.SUCCESS, f"{self.WHITE}{target:<12} {self.DIM}-> {self.SUCCESS}{detail}")

    def fail(self, text: str, **kwargs) -> None:
        if kwargs:
            self._log_status('-', self.FAIL, 'ERROR', self.FAIL, **kwargs)
        else:
            self.log_line('-', self.FAIL, text)

    def err(self, target: str, detail: str) -> None:
        self.log_line('-', self.FAIL, f"{self.WHITE}{target:<12} {self.DIM}-> {self.FAIL}{detail}")

    def warning(self, text: str, **kwargs) -> None:
        if kwargs:
            self._log_status('*', self.WARN, 'WARN', self.WARN, **kwargs)
        else:
            self.log_line('*', self.WARN, text)

    def warn(self, target: str, detail: str) -> None:
        self.log_line('*', self.WARN, f"{self.WHITE}{target:<12} {self.DIM}-> {self.WARN}{detail}")

    def sent(self, **kwargs) -> None:
        self._log_status('+', self.SUCCESS, 'SENT', self.SUCCESS, **kwargs)

    def input(self, text: str) -> None:
        time_str = f"{self.DIM}[{self.TIME_GRAY}{self.get_time()}{self.DIM}]{self.RESET}"
        pfx = self.prefix('?', self.PURPLE)
        print(f"\n{time_str} {pfx} {self.WHITE}{text}{self.RESET} ", end='', flush=True)

    def clear(self) -> None:
        os.system('cls' if os.name == 'nt' else 'clear')


def print_banner() -> None:
    os.system('cls' if os.name == 'nt' else 'clear')
    print()
    purple = "\033[38;5;141m"
    dim = "\033[38;5;239m"
    white = "\033[38;5;255m"
    reset = "\033[0m"
    print(f"  {purple}zenkai {dim}• {white}discord badge spoofer{reset}")
    print(f"  {dim}──────────────────────────────────────────{reset}")
    print()


def update_title(total_games: int = 0, total_hours: float = 0.0) -> None:
    if sys.platform == 'win32':
        try:
            import ctypes
            ctypes.windll.kernel32.SetConsoleTitleW(
                f'Discord Badge Spoofer | Claimed Games: {total_games} | Claimed Hours: {total_hours:,.0f}h'
            )
        except Exception:
            pass


def wait_for_enter() -> None:
    if sys.platform == 'win32':
        try:
            import msvcrt
            while True:
                if msvcrt.kbhit():
                    key = msvcrt.getch()
                    if key in (b'\r', b'\n'):
                        break
                time.sleep(0.05)
            print()
            return
        except Exception:
            pass
    input()
    print()


@dataclass
class State:
    token: str = ""
    cookie: str = ""
    fingerprint: str = ""
    analytics_token: str = ""
    fetched_at: int = 0
    used_games: list[str] = None
    total_games_claimed: int = 0
    total_hours_claimed: float = 0.0

    def __post_init__(self) -> None:
        if self.used_games is None:
            self.used_games = []

    @classmethod
    def load(cls) -> "State":
        if STATE_FILE.exists():
            try:
                data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
            except Exception:
                data = {}
            valid_keys = {f for f in cls().__dict__.keys() if f != "used_games"}
            state = cls(**{k: data[k] for k in valid_keys if k in data})
            state.used_games = data.get("used_games", [])
            return state
        return cls()

    def save(self) -> None:
        STATE_FILE.write_text(json.dumps(asdict(self), indent=2), encoding="utf-8")

    @property
    def is_stale(self) -> bool:
        return not self.analytics_token or (time.time() - self.fetched_at) > AUTH_MAX_AGE

    @property
    def has_cookie(self) -> bool:
        return bool(self.cookie.strip())

    @property
    def has_token(self) -> bool:
        return bool(self.token.strip())


def _local_props() -> dict:
    return {
        "os": "Windows",
        "browser": "Discord Client",
        "release_channel": "stable",
        "client_version": CLIENT_VERSION,
        "os_version": OS_VERSION,
        "os_arch": "x64",
        "app_arch": "x64",
        "system_locale": "en-GB",
        "has_client_mods": False,
        "browser_user_agent": USER_AGENT,
        "browser_version": "42.7.1",
        "os_sdk_version": "26200",
        "client_build_number": CLIENT_BUILD_NUMBER,
        "native_build_number": NATIVE_BUILD_NUMBER,
        "client_event_source": None,
        "client_app_state": "focused",
    }


def build_super_props(launch_signature: str, heartbeat_session: str) -> str:
    try:
        req = urllib.request.Request(PROPERTIES_URL, method="POST", data=b"{}",
                                     headers={"content-type": "application/json", "user-agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as response:
            props = json.loads(response.read().decode("utf-8"))["properties"]
    except Exception:
        props = _local_props()
    props["client_launch_id"] = str(uuid.uuid4())
    props["launch_signature"] = launch_signature
    props["client_heartbeat_session_id"] = heartbeat_session
    props["client_build_number"] = CLIENT_BUILD_NUMBER
    raw = json.dumps(props, separators=(",", ":")).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _read_analytics_token(auth_token: str, super_props: str) -> str:
    headers = {
        "authorization": auth_token,
        "user-agent": USER_AGENT,
        "x-super-properties": super_props,
    }
    if HAS_CURL_CFFI:
        try:
            resp = curl_requests.get(ME_URL, headers=headers, impersonate="chrome131", timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                token = data.get("analytics_token")
                if token:
                    return token
            elif resp.status_code in (401, 403):
                raise RuntimeError(f"token rejected ({resp.status_code})")
        except Exception as exc:
            if isinstance(exc, RuntimeError):
                raise

    req = urllib.request.Request(ME_URL, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"token rejected ({exc.code})") from exc
    token = data.get("analytics_token")
    if not token:
        raise RuntimeError("no analytics_token in response")
    return token


def ensure_token(state: State, super_props: str) -> None:
    if not state.is_stale:
        return
    state.analytics_token = _read_analytics_token(state.token, super_props)
    state.fetched_at = int(time.time())
    state.save()


@dataclass(frozen=True)
class Session:
    heartbeat_session: str
    launch_signature: str
    super_props: str

    @classmethod
    def new(cls) -> "Session":
        hb = str(uuid.uuid4())
        sig = str(uuid.uuid4())
        return cls(hb, sig, build_super_props(sig, hb))


@dataclass(frozen=True)
class Game:
    id: str
    name: str
    exe: str


def _win_exe(game: dict) -> str:
    for entry in game.get("executables", []):
        if entry.get("os") == "win32" and entry.get("name"):
            return entry["name"]
    return "game.exe"


def _download_games() -> str:
    request = urllib.request.Request(GAMES_CDN_URL, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode("utf-8")
    try:
        GAMES_FILE.parent.mkdir(parents=True, exist_ok=True)
        GAMES_FILE.write_text(raw, encoding="utf-8")
    except OSError:
        pass
    return raw


def _parse_games(raw: str) -> list[Game]:
    data = json.loads(raw)
    games: list[Game] = []
    seen: set[str] = set()
    for entry in data:
        gid = str(entry.get("id", ""))
        if not gid.isdigit() or gid in seen:
            continue
        if not any(e.get("os") == "win32" and e.get("name") for e in entry.get("executables", [])):
            continue
        seen.add(gid)
        games.append(Game(gid, entry.get("name", "Unknown"), _win_exe(entry)))
    return games


def load_games() -> list[Game]:
    raw = ""
    if GAMES_FILE.exists():
        raw = GAMES_FILE.read_text(encoding="utf-8").strip()
    if raw:
        try:
            games = _parse_games(raw)
            if games:
                return games
        except (json.JSONDecodeError, ValueError):
            pass
    try:
        return _parse_games(_download_games())
    except Exception:
        return []


class ScienceClient:
    def __init__(self, state: State, session: Session) -> None:
        self.state = state
        self.session = session
        self._seq = 0

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def build_launch(self, game: Game) -> dict:
        now = int(time.time() * 1000)
        props = {
            "client_track_timestamp": now,
            "client_heartbeat_session_id": self.session.heartbeat_session,
            "event_sequence_number": self._next_seq(),
            "game": game.name,
            "game_id": game.id,
            "verified": True,
            "elevated": False,
            "is_launcher": False,
            "game_platform": "desktop",
            "detection_method": "verified_game",
            "is_overlay_enabled": False,
            "is_overlay_game_enabled": True,
            "is_overlay_game_source": "OOP_DEFAULT_DATABASE",
            "fullscreen_type": "UNKNOWN",
            "hardware_display_count": 1,
            "overlay_method": "Disabled",
            "activity_status_enabled": True,
            "activity_status_shared_guilds": [],
            "current_user_status": "online",
            "game_detection_enabled": True,
            "executable_path": game.exe,
            "voice_channel_id": None,
            "voice_channel_type": None,
            "voice_channel_bitrate": None,
            "voice_channel_guild_id": None,
            "hidden_by_distributor": False,
            "game_metadata": None,
            "executable_fingerprint": self.state.fingerprint,
            "client_performance_cpu": None,
            "client_performance_memory": None,
            "cpu_core_count": None,
            "accessibility_features": 0,
            "rendered_locale": "en-GB",
            "launch_signature": self.session.launch_signature,
            "client_rtc_state": None,
            "client_app_state": "focused",
            "client_send_timestamp": now,
        }
        if not self.state.fingerprint:
            del props["executable_fingerprint"]
        return {"type": "launch_game", "properties": props}

    def build_heartbeat(self, game: Game, duration_ms: int, session_id: str,
                        initial: bool, final: bool, ts: int | None = None) -> dict:
        ts = int(time.time() * 1000) if ts is None else ts
        return {
            "type": "running_game_heartbeat",
            "properties": {
                "client_track_timestamp": ts,
                "client_heartbeat_session_id": self.session.heartbeat_session,
                "event_sequence_number": self._next_seq(),
                "game_id": game.id,
                "game_name": game.name,
                "game_metadata": None,
                "game_executable": game.exe,
                "game_detection_enabled": True,
                "initial_heartbeat": initial,
                "final_heartbeat": final,
                "game_session_id": session_id,
                "duration_tracked_ms": duration_ms,
                "rtc_connection_id": None,
                "media_session_id": None,
                "launch_signature": self.session.launch_signature,
                "client_app_state": "focused",
                "client_send_timestamp": ts,
            },
        }

    def build_session(self, game: Game, duration_ms: int) -> list[dict]:
        sid = str(uuid.uuid4())
        now = int(time.time() * 1000)
        start = now - duration_ms
        if start < 0:
            start = now
        return [
            self.build_heartbeat(game, 0, sid, initial=True, final=False, ts=start),
            self.build_launch(game),
            self.build_heartbeat(game, duration_ms, sid, initial=False, final=True, ts=now),
        ]

    def post(self, events: Sequence[dict], proxy: str = "") -> int:
        payload = {"token": self.state.analytics_token, "events": list(events)}
        body = json.dumps(payload).encode("utf-8")
        cookie_hdr = sanitize_cookie(self.state.cookie)
        headers = {
            "accept": "*/*",
            "accept-language": "en-GB",
            "authorization": self.state.token,
            "content-type": "application/json",
            "origin": "https://discord.com",
            "referer": "https://discord.com/channels/@me",
            "user-agent": USER_AGENT,
            "x-debug-options": "bugReporterEnabled",
            "x-discord-locale": "en-GB",
            "x-discord-timezone": "Europe/Oslo",
            "x-super-properties": self.session.super_props,
        }
        if cookie_hdr:
            headers["cookie"] = cookie_hdr
        if DEBUG:
            print("\n" + "=" * 72)
            print(f"POST {SCIENCE_URL} ({len(payload['events'])} events)")
            print("headers:", json.dumps(headers, indent=2))
            print("body:", json.dumps(payload, indent=2))
            print("=" * 72)

        if HAS_CURL_CFFI:
            try:
                kw = {"headers": headers, "data": body, "timeout": 15, "impersonate": "chrome131"}
                if proxy:
                    kw["proxies"] = {"http": proxy, "https": proxy}
                resp = curl_requests.post(SCIENCE_URL, **kw)
                return resp.status_code
            except Exception:
                return 0

        request = urllib.request.Request(SCIENCE_URL, data=body, method="POST", headers=headers)
        try:
            if proxy:
                handler = urllib.request.ProxyHandler({"http": proxy, "https": proxy})
                opener = urllib.request.build_opener(handler)
                with opener.open(request, timeout=15) as response:
                    return response.status
            else:
                with urllib.request.urlopen(request, timeout=15) as response:
                    return response.status
        except urllib.error.HTTPError as exc:
            return exc.code
        except Exception:
            return 0


def _chunked(items: Sequence[Game], size: int) -> Iterator[Sequence[Game]]:
    for start in range(0, len(items), size):
        yield items[start:start + size]


class Spoofer:
    def __init__(self, client: ScienceClient, logger: Logger, proxies: Sequence[str] = ()) -> None:
        self.client = client
        self.log = logger
        self.proxies = list(proxies)
        self.proxy_idx = 0

    def _next_proxy(self) -> str:
        if not self.proxies:
            return ""
        p = self.proxies[self.proxy_idx % len(self.proxies)]
        self.proxy_idx += 1
        return p

    def run(self, games: Sequence[Game], build_events) -> int:
        total = len(games)
        total_batches = (total + BATCH_SIZE - 1) // BATCH_SIZE
        sent_ok = 0
        batch_pad = max(len(str(total_batches)), 2)
        game_pad = len(f"{total:,}")
        for request_no, chunk in enumerate(_chunked(games, BATCH_SIZE), start=1):
            events = []
            for game in chunk:
                events.extend(build_events(game))
            proxy = self._next_proxy()
            status = self.client.post(events, proxy=proxy)
            if status == 204:
                sent_ok += len(chunk)
                pct = (sent_ok / total) * 100
                self.log.sent(
                    batch=f"{request_no:0{batch_pad}d}/{total_batches}",
                    games=f"{sent_ok:>{game_pad},}/{total:,}",
                    pct=f"{pct:5.1f}%",
                    status="SUCCESS",
                )
            elif status in (401, 403):
                self.log.fail(f"Auth rejected ({status})", batch=f"{request_no:0{batch_pad}d}/{total_batches}", status=status, error="refresh with cookie")
                return sent_ok
            else:
                self.log.warning(f"Unexpected status ({status})", batch=f"{request_no:0{batch_pad}d}/{total_batches}", status=status)
            time.sleep(BATCH_DELAY)
        return sent_ok


class App:
    def __init__(self) -> None:
        self.log = Logger()
        self.state = State.load()
        self.session: Session | None = None
        self.client: ScienceClient | None = None
        self.games: list[Game] = []
        self.proxies: list[str] = load_proxies()

    def start(self) -> None:
        update_title(self.state.total_games_claimed, self.state.total_hours_claimed)
        print_banner()
        self.log.inf(f"Engine -> {'curl_cffi (Chrome 131 impersonation)' if HAS_CURL_CFFI else 'urllib'}")
        self.log.inf(f"Discord Client Build -> {CLIENT_BUILD_NUMBER}")
        if self.proxies:
            self.log.inf(f"Proxies loaded -> count= {len(self.proxies)}")
        time.sleep(0.3)

        if not self.state.has_token:
            self._prompt_token()
        else:
            self.log.ok("auth", "token loaded")
            time.sleep(0.3)
        if not self.state.has_token:
            self.log.err("token", "required to run")
            return

        print_banner()
        self.log.inf("loading games...")
        time.sleep(0.3)
        self.games = load_games()
        if not self.games:
            self.log.err("games", "couldn't load the game list")
            self.log.inf(f"tried {GAMES_FILE} and {GAMES_CDN_URL}")
            self.log.inf("check your connection, or drop a valid games.json at the path above")
            return
        self.log.ok("games", f"{len(self.games):,} loaded")
        time.sleep(0.3)

        if not self.state.fingerprint:
            self.log.warn("fingerprint", "not set · script may not credit the badges")
            time.sleep(0.3)

        self.log.inf("validating auth...")
        self._new_session()
        try:
            ensure_token(self.state, self.session.super_props)
        except Exception as exc:
            self.log.err("token", str(exc))
            return
        self.log.ok("auth", "ready")
        time.sleep(0.5)

        self.menu()

    def _new_session(self) -> None:
        self.session = Session.new()
        self.client = ScienceClient(self.state, self.session)

    def _prompt_token(self) -> None:
        self.log.inf("paste your discord account token")
        self.log.input("token:")
        entered = input().strip()
        cleaned = sanitize_token(entered)
        if cleaned:
            self.state.token = cleaned
            self.state.save()
            self.log.ok("token", "saved")
            time.sleep(1.0)

    def _prompt_cookie(self) -> None:
        self.log.inf("paste your cf_clearance cookie header")
        self.log.input("cookie:")
        entered = input().strip()
        cleaned = sanitize_cookie(entered)
        if cleaned:
            self.state.cookie = cleaned
            self.state.save()
            self.log.ok("cookie", "saved")
            time.sleep(1.0)

    def _refresh(self) -> None:
        self.log.input("update token? [y/n]:")
        choice = input().strip().lower()
        if choice in ("y", "yes"):
            self._prompt_token()

        self.log.input("update cookie? (optional) [y/n]:")
        choice = input().strip().lower()
        if choice in ("y", "yes"):
            self.log.input("paste fresh cookie header:")
            entered = input().strip()
            cleaned = sanitize_cookie(entered)
            if cleaned:
                self.state.cookie = cleaned
                self.log.ok("cookie", "updated")
            else:
                self.log.inf("cookie unchanged")

        self.log.inf("refreshing analytics token...")
        try:
            self.state.fetched_at = 0
            ensure_token(self.state, self.session.super_props)
        except Exception as exc:
            self.log.err("auth", str(exc))
            return
        self._new_session()
        self.state.save()
        self.log.ok("auth", "refreshed")
        time.sleep(1.0)

    def _require_ready(self) -> bool:
        if not self.state.has_token:
            self.log.err("token", "not set")
            return False
        if self.state.is_stale:
            try:
                ensure_token(self.state, self.session.super_props)
            except Exception as exc:
                self.log.err("auth", str(exc))
                return False
            self._new_session()
        return bool(self.state.analytics_token)

    def claim_playtime(self) -> None:
        self._claim_flow(mode_name="Playtime Badge", default_hours=1.0, is_fixed_hours=False)

    def claim_games_played(self) -> None:
        self._claim_flow(mode_name="Variety Badge", default_hours=(1.0 / 60.0), is_fixed_hours=True)

    def _claim_flow(self, mode_name: str, default_hours: float, is_fixed_hours: bool) -> None:
        if not self._require_ready():
            return
        print()
        self.log.inf(f"Available games -> count= {len(self.games):,}")

        self.log.input(f"How many games? [{len(self.games)}]:")
        raw_count = input().strip()
        try:
            count = int(raw_count) if raw_count else len(self.games)
        except ValueError:
            self.log.err("input", "invalid count")
            return
        count = min(count, len(self.games))

        if is_fixed_hours:
            hours = default_hours
        else:
            self.log.input(f"Hours per game? [{default_hours:g}]:")
            raw_hours = input().strip()
            try:
                hours = float(raw_hours) if raw_hours else default_hours
            except ValueError:
                self.log.err("input", "invalid hours")
                return

        selected = self._select_games(count)
        if not selected:
            self.log.err("games", "none selected")
            return

        duration_ms = max(60000, int(hours * 3600 * 1000))
        total_hours = len(selected) * hours
        print()
        if is_fixed_hours:
            self.log.inf(f"Starting {mode_name} claim -> games= {len(selected):,} (1m per game)")
        else:
            self.log.inf(
                f"Starting {mode_name} claim -> games= {len(selected):,}, hours_per_game= {hours:g}h, total_hours= {total_hours:,.0f}h"
            )
        print()
        ok = Spoofer(self.client, self.log, proxies=self.proxies).run(
            selected,
            lambda g: self.client.build_session(g, duration_ms),
        )
        print()
        self.log.log_line(
            '+',
            self.log.SUCCESS,
            f"{self.log.WHITE}Claim Complete {self.log.DIM}-> {self.log.SUCCESS}{ok:,}/{len(selected):,} games {self.log.DIM}• {self.log.INFO}{ok * hours:,.1f}h total{self.log.RESET}"
        )
        self.state.total_games_claimed += ok
        self.state.total_hours_claimed += ok * hours
        self.state.save()
        update_title(self.state.total_games_claimed, self.state.total_hours_claimed)

        self.log.input("Press Enter to continue")
        wait_for_enter()

    def _select_games(self, count: int) -> list[Game]:
        available_ids = {g.id for g in self.games}
        unused_ids = [g.id for g in self.games if g.id not in self.state.used_games]
        used_ids = [gid for gid in self.state.used_games if gid in available_ids]

        if len(unused_ids) >= count:
            selected_ids = unused_ids[:count]
        else:
            selected_ids = unused_ids
            if used_ids:
                remaining = count - len(selected_ids)
                rotated = used_ids[remaining:] + used_ids[:remaining]
                selected_ids.extend(rotated[:remaining])

        self.state.used_games = [gid for gid in self.state.used_games if gid not in selected_ids] + selected_ids

        id_map = {g.id: g for g in self.games}
        return [id_map[gid] for gid in selected_ids if gid in id_map]

    def set_fingerprint(self) -> None:
        uid = _user_id_from_token(self.state.token)
        if not uid:
            self.log.err("fingerprint", "no valid token · set one first")
            time.sleep(1.5)
            return
        if os.name != "nt":
            self.log.err("fingerprint", "windows-only feature")
            time.sleep(1.5)
            return
        self.log.inf(f"Generate executable_fingerprint -> user_id= {uid}")
        self.log.inf("Target game .exe path or running PID")
        self.log.input("Exe path or PID:")
        entered = input().strip().strip('"')
        if not entered:
            self.log.inf("cancelled")
            time.sleep(1.0)
            return
        pid = int(entered) if entered.isdigit() else 0
        path = "" if pid else entered
        if path and not Path(path).exists():
            self.log.err("fingerprint", f"file not found: {path}")
            time.sleep(1.5)
            return
        self.log.inf("generating...")
        try:
            fp = generate_fingerprint(uid, path=path, pid=pid)
        except Exception as exc:
            self.log.err("fingerprint", str(exc))
            time.sleep(2.0)
            return
        self.state.fingerprint = fp
        self.state.save()
        self.log.ok("fingerprint", f"set ({len(fp)} chars) · saved to {STATE_FILE.name}")
        time.sleep(1.5)

    def menu(self) -> None:
        dim = self.log.DIM
        gray = self.log.TIME_GRAY
        white = self.log.WHITE
        purple = self.log.PURPLE
        reset = self.log.RESET

        while True:
            update_title(self.state.total_games_claimed, self.state.total_hours_claimed)
            print_banner()
            time_str = f"{dim}[{gray}{self.log.get_time()}{dim}]{reset}"
            pfx = self.log.prefix('/', self.log.INFO)
            print(f"{time_str} {pfx} {self.log.WHITE}Menu Options{reset}")
            print(f"{time_str}      {dim}├── {purple}[1]{reset} {white}Claim Games Playtime Badge{reset}")
            print(f"{time_str}      {dim}├── {purple}[2]{reset} {white}Claim Games Variety Badge{reset}")
            print(f"{time_str}      {dim}├── {purple}[3]{reset} {white}Refresh Auth{reset}")
            print(f"{time_str}      {dim}├── {purple}[4]{reset} {white}Set Fingerprint{reset}")
            print(f"{time_str}      {dim}└── {purple}[5]{reset} {white}Exit{reset}")

            self.log.input("Select option:")
            choice = input().strip()
            print()
            if choice == "1":
                self.claim_playtime()
            elif choice == "2":
                self.claim_games_played()
            elif choice == "3":
                self._refresh()
            elif choice == "4":
                self.set_fingerprint()
            elif choice in ("5", "exit", "quit"):
                break
            else:
                self.log.warning("Invalid option")
                time.sleep(1.0)


def main() -> None:
    try:
        App().start()
    except KeyboardInterrupt:
        print()
        log = Logger()
        log.warning("interrupted by user, exiting")


if __name__ == "__main__":
    main()
