#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
NetMon Pro — Édition Enterprise (Tout-en-un)
Version : 16.0 (2025-08-12)

Auteur : Chaouki Boussayri
© 2025 — Tous droits réservés

Résumé
------
Script unique, propre et robuste :
- Relance automatique en **Administrateur** (UAC) dès le démarrage.
- Installe automatiquement les **dépendances pip** nécessaires.
- Vérifie/installe **winget**, **Chocolatey**, **Npcap** (site officiel → winget → choco).
- Interface moderne (Tkinter + matplotlib) avec :
  * Tableau de bord (CPU/RAM/Internet) + journal.
  * Performances temps réel (CPU, Mémoire, Bande passante).
  * Cartographie réseau (NetworkX).
  * Sniffer Scapy (Npcap requis).
  * Scan ports & sécurité (heuristiques vulnérabilités basiques).
  * Supervision type PRTG/Zabbix (capteurs PING/PORT/HTTP/SNMP).
  * Maintenance Windows (SFC/DISM/CHKDSK/Reset WU/Net/Firewall/Store/Temp/Safe Mode).
  * Inventaire logiciels (winget list) + journaux Windows.
  * Rapports PDF.
  * Profils & Alertes.
  * Catalogue d’outils Open Source (winget/choco) installables en 1 clic.
- Signature **RGPD obligatoire** (persistée localement).

Journal : %LocalAppData%\\NetMonPro\\netmon.log
"""

# ======================== IMPORTS LÉGERS & SETUP ========================
import os, sys, time, json, queue, socket, ipaddress, threading, subprocess, platform, webbrowser, shutil, logging, importlib.util, re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field

APP_NAME = "NetMon Pro"
VERSION = "16.0"
CONSENT_FILE = os.path.join(os.path.expanduser("~"), ".netmon_pro_gdpr.json")
DATA_DIR = os.path.join(os.getenv("LOCALAPPDATA", os.path.expanduser("~")), "NetMonPro")
os.makedirs(DATA_DIR, exist_ok=True)
LOG_PATH = os.path.join(DATA_DIR, "netmon.log")
PROFILE_PATH = os.path.join(DATA_DIR, "profile.json")

logging.basicConfig(filename=LOG_PATH, filemode="a", level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

# ======================== UTILITAIRES OS / PRIVILÈGES ===================
def is_windows() -> bool: return platform.system().lower() == "windows"

def is_admin() -> bool:
    if not is_windows(): return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def relaunch_as_admin():
    """Relance le script en mode Administrateur (UAC) et termine le processus courant."""
    if not is_windows(): return
    import ctypes
    params = " ".join([f'"{a}"' for a in sys.argv])
    try:
        ctypes.windll.user32.MessageBoxW(
            None,
            "Ce programme doit s'exécuter en administrateur.\n"
            "Cliquez 'Oui' dans l’invite UAC.\n"
            f"Journal : {LOG_PATH}",
            "NetMon Pro - Élévation requise",
            0x40
        )
    except Exception:
        pass
    logger.info("Relance en mode admin avec paramètres: %s", params)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)
    if rc <= 32:
        try: ctypes.windll.user32.MessageBoxW(None, f"Échec d'élévation (rc={rc}).\nLog : {LOG_PATH}", "NetMon Pro", 0x10)
        except Exception: pass
    sys.exit(0)

def has_command(cmd: str) -> bool: return shutil.which(cmd) is not None

def run_ps_inline(cmd: str, elevated: bool=False, timeout: int=0) -> int:
    """Exécute PowerShell. Si elevated=True, écrit le script dans un .ps1 temporaire
    et lance un PowerShell élevé avec -File, en attendant la fin, puis renvoie ExitCode.
    Cette méthode supprime tous les problèmes de quoting de -ArgumentList.
    """
    logger.info("PS%s: %s", " (elev)" if elevated else "", cmd)
    base = ["powershell","-NoProfile","-ExecutionPolicy","Bypass","-Command"]
    try:
        if elevated and is_windows():
            import tempfile
            # écrire dans un script temporaire
            with tempfile.NamedTemporaryFile(delete=False, suffix=".ps1", mode="w", encoding="utf-8") as tf:
                tf.write(cmd + "\n")
                tf.write("\nexit $LASTEXITCODE\n")
                script_path = tf.name
            ps_code = (
                "$p = Start-Process -FilePath 'PowerShell' -Verb RunAs -PassThru "
                "-ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File', '{}'); "
                "$p.WaitForExit(); exit $p.ExitCode"
            ).format(script_path.replace("'", "''"))
            args = base + [ps_code]
            try:
                if timeout and timeout > 0:
                    cp = subprocess.run(args, timeout=timeout)
                    rc = cp.returncode
                else:
                    rc = subprocess.call(args)
            finally:
                try: os.remove(script_path)
                except Exception: pass
            return rc
        else:
            args = base + [cmd]
            if timeout and timeout > 0:
                cp = subprocess.run(args, timeout=timeout)
                return cp.returncode
            return subprocess.call(args)
    except Exception:
        logger.exception("run_ps_inline failed")
        return 1

# ======================== DÉPENDANCES PIP ===============================
REQUIRED_PIP = ["psutil", "matplotlib", "reportlab", "networkx", "scapy", "pysnmp"]

def ensure_pip_dependencies():
    """Installe les dépendances pip manquantes avec une petite stratégie de retry."""
    try:
        missing = [p for p in REQUIRED_PIP if importlib.util.find_spec(p) is None]
        if not missing: return
        logger.info("Installation pip des deps manquantes: %s", ", ".join(missing))
        # tenter upgrade pip silencieux (best effort)
        try:
            subprocess.run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"], check=False)
        except Exception:
            pass
        # installer en une fois
        rc = subprocess.call([sys.executable, "-m", "pip", "install", *missing])
        if rc != 0:
            # retry une par une
            for pkg in missing:
                try:
                    subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
                except Exception:
                    logger.exception("pip install échec pour %s", pkg)
    except Exception:
        logger.exception("pip install failed")

# ======================== WINGET / CHOCOLATEY ===========================
def winget_path() -> Optional[str]:
    """Renvoie le chemin de winget.exe (WindowsApps) ou 'winget' si dans PATH; sinon None."""
    if has_command("winget"): return "winget"
    wapp = os.path.join(os.getenv("LOCALAPPDATA",""), "Microsoft", "WindowsApps", "winget.exe")
    return wapp if os.path.isfile(wapp) else None

def ensure_winget() -> Tuple[bool, str]:
    if not is_windows(): return (False, "winget non applicable.")
    if winget_path(): return (True, "winget déjà présent.")
    ps = (
        "$ProgressPreference='SilentlyContinue';"
        "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;"
        "$tmp = Join-Path $env:TEMP 'winget_inst'; New-Item -ItemType Directory -Force -Path $tmp | Out-Null;"
        "$vcl = Join-Path $tmp 'VCLibs.appx';"
        "Invoke-WebRequest -Uri 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx' -OutFile $vcl -UseBasicParsing;"
        "Try { Add-AppxPackage -Path $vcl } Catch { Write-Host 'VCLibs install warn: ' $_.Exception.Message };"
        "$appxb = Join-Path $tmp 'AppInstaller.msixbundle';"
        "Invoke-WebRequest -Uri 'https://aka.ms/getwinget' -OutFile $appxb -UseBasicParsing;"
        "Try { Add-AppxPackage -Path $appxb -ForceApplicationShutdown -ForceUpdateFromAnyVersion } Catch { Write-Host 'AppInstaller warn: ' $_.Exception.Message };"
        "Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue;"
    )
    rc = run_ps_inline(ps, elevated=True, timeout=900)
    # Refresh PATH for current process
    os.environ["PATH"] = os.environ.get("PATH","") + os.pathsep + os.path.join(os.getenv("LOCALAPPDATA",""), "Microsoft", "WindowsApps")
    if winget_path(): return (True, "winget installé.")
    try: webbrowser.open('ms-windows-store://pdp/?productid=9NBLGGH4NNS1')
    except Exception: pass
    return (False, "Impossible d'installer winget automatiquement.")

def ensure_chocolatey() -> Tuple[bool, str]:
    if not is_windows(): return (False, "Chocolatey non applicable.")
    if has_command("choco"): return (True, "Chocolatey déjà installé.")
    ps = ("Set-ExecutionPolicy Bypass -Scope Process -Force; "
          "[System.Net.ServicePointManager]::SecurityProtocol = "
          "[System.Net.ServicePointManager]::SecurityProtocol -bor 3072; "
          "iwr https://community.chocolatey.org/install.ps1 -UseBasicParsing | iex")
    rc = run_ps_inline(ps, elevated=True, timeout=600)
    if rc == 0 and has_command("choco"): return (True, "Chocolatey installé.")
    return (False, "Échec installation Chocolatey.")

# ======================== NPCAP / PCAP ==================================
def _npcap_download_official() -> Tuple[bool, str]:
    """Télécharge l’installeur Npcap depuis npcap.com et retourne le chemin local."""
    if not is_windows(): return (False, "Npcap non applicable.")
    ps = r"""
$ProgressPreference='SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
try {
  $u1='https://npcap.com/#download'
  $html=Invoke-WebRequest -Uri $u1 -UseBasicParsing
  $link=($html.Links|?{$_.href -match 'npcap-.*\.exe'}|select -First 1).href
  if(-not $link){
    $u2='https://npcap.com/'
    $html=Invoke-WebRequest -Uri $u2 -UseBasicParsing
    $link=($html.Links|?{$_.href -match 'npcap-.*\.exe'}|select -First 1).href
  }
  if(-not $link){'NO_LINK'; exit 2}
  if($link -notmatch '^https?://'){ $link='https://npcap.com'+$link }
  $dst=Join-Path $env:TEMP 'npcap-setup.exe'
  Invoke-WebRequest -Uri $link -OutFile $dst -UseBasicParsing
  $dst; exit 0
}catch{ 'ERR:'+$_.Exception.Message; exit 1 }
"""
    try:
        cp = subprocess.run(["powershell","-NoProfile","-ExecutionPolicy","Bypass","-Command",ps],
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=300)
        out = (cp.stdout or "").strip().splitlines()[-1] if cp.stdout else ""
        if out.startswith("NO_LINK"): return (False, "Lien Npcap introuvable.")
        if out.startswith("ERR:"): return (False, out)
        if os.path.exists(out): return (True, out)
        return (False, f"Fichier Npcap non trouvé: {out}")
    except Exception as e:
        return (False, f"Echec téléchargement Npcap: {e}")

def install_npcap_official(oem_silent: bool=False, extra_args: str="") -> Tuple[bool, str]:
    ok, path = _npcap_download_official()
    if not ok: return (False, path)
    args = f'/S {extra_args}'.strip() if oem_silent else ""
    if args:
        rc = run_ps_inline(f'Start-Process -Verb RunAs -FilePath "{path}" -ArgumentList "{args}" -Wait; $LASTEXITCODE', elevated=False)
    else:
        rc = run_ps_inline(f'Start-Process -Verb RunAs -FilePath "{path}" -Wait; $LASTEXITCODE', elevated=False)
    if rc == 0: return (True, "Npcap installé depuis npcap.com.")
    return (False, f"Installeur Npcap retour {rc}.")

def install_npcap() -> Tuple[bool, str]:
    """Tente l'installation de Npcap (site officiel → winget → choco)."""
    if not is_windows(): return (False, "Npcap non applicable.")
    oem = os.environ.get("NPCAP_OEM","0")=="1"
    extra = os.environ.get("NPCAP_OEM_ARGS","")
    ok,msg = install_npcap_official(oem_silent=oem, extra_args=extra)
    if ok: return (True, msg+" (site officiel)")
    wp = winget_path()
    if wp:
        rc = run_ps_inline(f'& "{wp}" install Nmap.Npcap --silent --accept-package-agreements --accept-source-agreements', elevated=True)
        if rc == 0: return (True, "Npcap installé via winget.")
    if not has_command("choco"): ensure_chocolatey()
    rc = run_ps_inline("choco install npcap -y", elevated=True)
    if rc == 0: return (True, "Npcap installé via Chocolatey.")
    try: webbrowser.open("https://npcap.com/#download")
    except Exception: pass
    return (False, "Npcap non installé automatiquement (page ouverte).")

def refresh_pcap_status() -> Tuple[bool, bool]:
    try:
        from scapy.all import conf as _conf  # noqa
        return True, bool(getattr(_conf, "use_pcap", False))
    except Exception:
        return False, False

# ======================== BOOTSTRAP (ADMIN+INSTALL) =====================
def bootstrap_startup():
    if is_windows() and not is_admin(): relaunch_as_admin()
    ensure_pip_dependencies()
    w_ok, w_msg = ensure_winget(); logger.info("[winget] %s", w_msg)
    c_ok, c_msg = ensure_chocolatey(); logger.info("[choco]  %s", c_msg)
    n_ok, n_msg = install_npcap(); logger.info("[npcap]  %s", n_msg)

# ======================== CHARGEMENT PARESSEUX (LIBS) ===================
def load_runtime_libs():
    """Charge toutes les libs lourdes APRÈS ensure_pip_dependencies()."""
    global psutil, _dt, nx, Figure, FigureCanvasTkAgg, A4, cm, canvas, SCAPY_OK, PCAP_OK
    global tk, ttk, scrolledtext, filedialog, messagebox

    import importlib
    psutil = importlib.import_module("psutil")
    _dt = importlib.import_module("datetime")

    nx = importlib.import_module("networkx")
    import matplotlib
    matplotlib.use("TkAgg")
    from matplotlib.figure import Figure as _Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg as _Canvas
    Figure, FigureCanvasTkAgg = _Figure, _Canvas

    # reportlab
    from reportlab.lib.pagesizes import A4 as _A4
    from reportlab.lib.units import cm as _cm
    from reportlab.pdfgen import canvas as _canvas
    A4, cm, canvas = _A4, _cm, _canvas

    # tkinter (stdlib)
    import tkinter as tk_
    from tkinter import ttk as ttk_
    from tkinter import scrolledtext as scrolledtext_
    from tkinter import filedialog as filedialog_
    from tkinter import messagebox as messagebox_
    tk, ttk, scrolledtext, filedialog, messagebox = tk_, ttk_, scrolledtext_, filedialog_, messagebox_

    # scapy status
    try:
        from scapy.all import conf as _conf  # noqa
        SCAPY_OK, PCAP_OK = True, bool(getattr(_conf, "use_pcap", False))
    except Exception:
        SCAPY_OK, PCAP_OK = False, False

# ======================== THÈME / UI ====================================
class Theme:
    COLORS = {
        # Thème joyeux/contrasté
        'bg': '#0b1220', 'panel': '#60a5fa', 'panel_fg': '#0b1220', 'fg': '#f8fafc',
        'accent': '#fbbf24', 'accent2': '#34d399', 'accent3': '#a78bfa',
        'ok': '#10b981', 'warn': '#f59e0b', 'err': '#ef4444', 'muted': '#94a3b8',
        'rgpd_label': '#f8fafc', 'rgpd_required': '#fde68a', 'rgpd_hint': '#e9d5ff',
        'rgpd_entry_bg': '#fff1f2', 'rgpd_entry_fg': '#111827', 'rgpd_entry_insert': '#ec4899',
        'section': '#0ea5e9'
    }
    FONTS = {'title': ('Segoe UI', 20, 'bold'), 'h': ('Segoe UI', 12, 'bold'), 'base': ('Segoe UI', 10), 'mono': ('Consolas', 10)}
    @classmethod
    def apply(cls, root: 'tk.Tk'):
        style=ttk.Style(); style.theme_use("clam")
        style.configure(".", background=cls.COLORS['bg'], foreground=cls.COLORS['fg'], font=cls.FONTS['base'])
        style.configure("TFrame", background=cls.COLORS['bg'])
        style.configure("TLabel", background=cls.COLORS['bg'], foreground=cls.COLORS['fg'])
        style.configure("TButton", background=cls.COLORS['accent'], foreground="#111827", padding=7)
        style.map("TButton", background=[("active", cls.COLORS['accent2']), ("pressed", cls.COLORS['accent3'])])
        style.configure("TLabelframe", background=cls.COLORS['panel'], foreground=cls.COLORS['panel_fg'], padding=10)
        style.configure("TLabelframe.Label", font=cls.FONTS['h'], background=cls.COLORS['panel'], foreground=cls.COLORS['panel_fg'])
        style.configure("Treeview", background="#082f49", foreground="#e2e8f0", fieldbackground="#082f49")
        style.configure("Treeview.Heading", background=cls.COLORS['accent3'], foreground="#111827")
        style.configure("TEntry", fieldbackground=cls.COLORS['rgpd_entry_bg'], foreground=cls.COLORS['rgpd_entry_fg'])
        root.option_add('*Text.background', "#0b3b3b"); root.option_add('*Text.foreground', "#e0f2f1")
        root.option_add('*Text.insertBackground', cls.COLORS['accent']); root.option_add('*Text.selectBackground', cls.COLORS['accent2'])
        root.option_add('*Text.font', cls.FONTS['mono']); root.option_add('*Entry.insertBackground', cls.COLORS['rgpd_entry_insert'])

# ======================== OUTILS RÉSEAU / SÉCURITÉ ======================
def get_primary_ipv4() -> Tuple[Optional[str], Optional[str]]:
    for iface, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith("127."):
                return a.address, a.netmask
    return None, None

def ping(host: str, count: int=1, timeout: float=0.8) -> bool:
    param_c='-n' if os.name=='nt' else '-c'
    param_w='-w' if os.name=='nt' else '-W'
    try:
        r = subprocess.run(["ping", param_c, str(count), param_w, str(int(timeout*1000) if os.name=='nt' else int(timeout)), host],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout+1.5)
        return r.returncode==0
    except Exception:
        return False

def traceroute(host: str, max_hops: int=20, timeout: int=3) -> str:
    try:
        if is_windows():
            cp = subprocess.run(["tracert","-d","-h",str(max_hops),host], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout*max_hops)
        else:
            cp = subprocess.run(["traceroute","-n","-m",str(max_hops),host], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout*max_hops)
        return cp.stdout or ""
    except Exception as e:
        return f"Erreur traceroute: {e}"

def port_scan(host: str, ports: List[int], timeout: float=0.6) -> Dict[int,str]:
    res={}
    for p in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host,p))==0:
                    banner=""
                    try:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n"); data=s.recv(256)
                        banner=data.decode(errors="ignore").strip().replace("\r"," ").replace("\n"," ")[:200]
                    except Exception: pass
                    res[p]=banner or "open"
        except Exception:
            pass
    return res

VULN_RULES=[(21,"","FTP en clair (21)"),(22,"OpenSSH_5.","OpenSSH ancien (<7)"),(23,"","Telnet non chiffré (23)"),
            (80,"Apache/2.2","Apache 2.2 ancien"),(110,"","POP3 en clair"),
            (139,"","SMBv1 possible (139)"),(445,"Samba 3.","Samba 3.x vulnérable"),(3389,"","RDP exposé"),(5900,"","VNC exposé")]
def evaluate_vulns(open_ports: Dict[int,str]) -> List[str]:
    out=[]
    for port,banner in open_ports.items():
        for prt,kw,msg in VULN_RULES:
            if port==prt and (kw=="" or kw.lower() in banner.lower()):
                out.append(f"[{port}] {msg}")
    return out

# ======================== MONITEURS =====================================
class BandwidthMonitor:
    def __init__(self): self.prev=None; self.speeds=(0.0,0.0); self.running=False
    def _snap(self): c=psutil.net_io_counters(); return (c.bytes_recv,c.bytes_sent,time.time())
    def start(self):
        if self.running: return
        self.running=True; self.prev=self._snap()
        threading.Thread(target=self._loop,daemon=True).start()
    def stop(self): self.running=False
    def _loop(self):
        while self.running:
            time.sleep(1.0); now=self._snap(); pr=self.prev
            if pr:
                dr=max(0,now[0]-pr[0]); ds=max(0,now[1]-pr[1]); dt=max(1e-6,now[2]-pr[2]); self.speeds=(dr/dt,ds/dt)
            self.prev=now

class NetworkScanner:
    def __init__(self): self.results: List[Tuple[str, Optional[str], float]] = []
    def scan_local(self, timeout: float=0.3, workers: int=128):
        self.results.clear(); ip,mask=get_primary_ipv4()
        if not ip or not mask: return
        try: net=ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        except Exception: return
        hosts=[str(h) for h in net.hosts()]; lock=threading.Lock(); threads=[]
        def worker(target:str):
            t0=time.time()
            if ping(target,1,timeout):
                lat=(time.time()-t0)*1000.0
                try: fqdn=socket.getfqdn(target); fqdn=None if fqdn==target else fqdn
                except Exception: fqdn=None
                with lock: self.results.append((target,fqdn,lat))
        for h in hosts:
            while len(threads)>=workers: threads[0].join(); threads.pop(0)
            th=threading.Thread(target=worker,args=(h,),daemon=True); threads.append(th); th.start()
        for th in threads: th.join()
    def build_graph(self):
        import networkx as nx
        G=nx.Graph(); my_ip,_=get_primary_ipv4()
        if my_ip: G.add_node(my_ip,role="local",label="Moi")
        for ip,host,lat in self.results:
            G.add_node(ip,role="host",label=host or ip)
            if my_ip: G.add_edge(my_ip,ip,latency=lat)
        return G

class PacketSniffer:
    def __init__(self): self.running=False; self.queue=queue.Queue(); self.thread=None
    def start(self, iface: Optional[str]=None, bpf: Optional[str]=None):
        ok,pcap = refresh_pcap_status()
        if not ok: self.queue.put("[Sniffer] Scapy indisponible (non importée)."); return
        if not pcap: self.queue.put("[Sniffer] Avertissement : Npcap/libpcap non détecté.")
        if self.running: return
        self.running=True
        def _cb(pkt):
            if not self.running: return
            try:
                proto="OTHER"
                try:
                    from scapy.layers.inet import ICMP
                    if pkt.haslayer(ICMP): proto="ICMP"
                except Exception: pass
                if 'ARP' in pkt: proto="ARP"
                elif 'TCP' in pkt: proto="TCP"
                elif 'UDP' in pkt: proto="UDP"
                self.queue.put(f"[{proto}] "+pkt.summary())
            except Exception as e: self.queue.put(f"[Sniffer] Erreur: {e}")
        def _run():
            try:
                from scapy.all import sniff
                sniff(prn=_cb, store=False, filter=bpf, iface=iface)
            except Exception as e:
                self.queue.put(f"[Sniffer] Erreur capture: {e}")
        self.thread=threading.Thread(target=_run,daemon=True); self.thread.start()
    def stop(self): self.running=False

# ======================== SUPERVISION ===================================
@dataclass
class SensorResult:
    status: str="UNKNOWN"; latency_ms: float=0.0; last_error: str=""

@dataclass
class BaseSensor:
    name: str; kind: str; target: str; interval: int=60; enabled: bool=True
    last_run: float=0.0; ok_count: int=0; fail_count: int=0; result: SensorResult = field(default_factory=SensorResult)
    def run(self): raise NotImplementedError

class PingSensor(BaseSensor):
    def __init__(self,name,target,interval=60): super().__init__(name,"PING",target,interval)
    def run(self):
        t0=time.time(); ok=ping(self.target,1,0.8); lat=(time.time()-t0)*1000.0
        if ok: self.ok_count+=1; self.result=SensorResult("UP",lat,"")
        else: self.fail_count+=1; self.result=SensorResult("DOWN",0.0,"No reply")

class PortSensor(BaseSensor):
    def __init__(self,name,target,port,interval=60): super().__init__(name,"PORT",f"{target}:{port}",interval); self.port=int(port)
    def run(self):
        t0=time.time(); ok=False
        try:
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
                s.settimeout(0.8); ok=(s.connect_ex((self.target.split(':')[0], self.port))==0)
        except Exception as e: _=e
        lat=(time.time()-t0)*1000.0
        if ok: self.ok_count+=1; self.result=SensorResult("OPEN",lat,"")
        else: self.fail_count+=1; self.result=SensorResult("CLOSED",0.0,"No connect")

class HttpSensor(BaseSensor):
    def __init__(self,name,url,interval=60): super().__init__(name,"HTTP",url,interval)
    def run(self):
        t0=time.time(); ok=False; err=""
        try:
            if has_command("curl"):
                cp=subprocess.run(["curl","-I","--max-time","3","-sS",self.target],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=5)
                out=(cp.stdout or "")
                ok=(" 200 " in out) or ("HTTP/2 200" in out)
                err = "" if ok else out[:120]
            else:
                import urllib.request
                with urllib.request.urlopen(self.target,timeout=3) as r: ok=(200<=r.status<400)
        except Exception as e: err=str(e)[:120]
        lat=(time.time()-t0)*1000.0
        if ok: self.ok_count+=1; self.result=SensorResult("OK",lat,"")
        else: self.fail_count+=1; self.result=SensorResult("FAIL",0.0,err)

class SNMPSensor(BaseSensor):
    def __init__(self,name,host,community="public",oid="1.3.6.1.2.1.1.1.0",interval=120):
        super().__init__(name,"SNMP",f"{host}|{community}|{oid}",interval); self.host=host; self.community=community; self.oid=oid
    def run(self):
        t0=time.time(); ok=False; err=""
        try:
            from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, getCmd
            it = getCmd(SnmpEngine(), CommunityData(self.community), UdpTransportTarget((self.host, 161), timeout=1, retries=0),
                        ContextData(), ObjectType(ObjectIdentity(self.oid)))
            errorIndication, errorStatus, errorIndex, varBinds = next(it)
            if errorIndication: err=str(errorIndication)
            elif errorStatus: err=str(errorStatus.prettyPrint())
            else: ok=True
        except Exception as e: err=str(e)
        lat=(time.time()-t0)*1000.0
        if ok: self.ok_count+=1; self.result=SensorResult("OK",lat,"")
        else: self.fail_count+=1; self.result=SensorResult("FAIL",0.0,err[:120])

class Supervisor:
    def __init__(self): self.sensors: List[BaseSensor]=[]; self.running=False
    def add(self,s:BaseSensor): self.sensors.append(s)
    def start(self):
        if self.running: return
        self.running=True; threading.Thread(target=self._loop,daemon=True).start()
    def stop(self): self.running=False
    def _loop(self):
        while self.running:
            now=time.time()
            for s in self.sensors:
                if s.enabled and now - s.last_run >= s.interval:
                    try: s.run()
                    except Exception as e: s.result=SensorResult("ERROR",0.0,str(e)[:120])
                    s.last_run=now
            time.sleep(0.5)

# ======================== RAPPORTS ======================================
class ReportBuilder:
    def build_pdf(self, path: str, meta: dict, devices, open_ports, vulns, diagnostics, sensors: List[BaseSensor]):
        c=canvas.Canvas(path,pagesize=A4); W,H=A4; m=2*cm; y=H-m
        def line(txt,size=10,step=14):
            nonlocal y; c.setFont("Helvetica",size); c.drawString(m,y,txt); y-=step
            if y<m: c.showPage(); y=H-m
        c.setFont("Helvetica-Bold",16); c.drawString(m,y,"Rapport NetMon Pro"); y-=24
        c.setFont("Helvetica",10); line(f"Généré: {_dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        for k,v in meta.items(): line(f"{k}: {v}"); y-=2
        c.setFont("Helvetica-Bold",12); c.drawString(m,y,"Appareils détectés"); y-=18; c.setFont("Helvetica",10)
        for ip,host,lat in sorted(devices): line(f"{ip}  {('('+host+') ' if host else '')}- {lat:.0f} ms")
        y-=6; c.setFont("Helvetica-Bold",12); c.drawString(m,y,"Ports ouverts"); y-=18; c.setFont("Helvetica",10)
        for host,ports in open_ports.items():
            line(f"[{host}]")
            for p,b in sorted(ports.items()): line(f"  {p}: {b[:90]}")
        y-=6; c.setFont("Helvetica-Bold",12); c.drawString(m,y,"Observations sécurité"); y-=18; c.setFont("Helvetica",10)
        for host,items in vulns.items():
            line(f"[{host}]")
            for it in items: line(f"  - {it}")
        y-=6; c.setFont("Helvetica-Bold",12); c.drawString(m,y,"Diagnostics"); y-=18; c.setFont("Helvetica",10)
        for d in diagnostics: line(f"- {d}")
        y-=6; c.setFont("Helvetica-Bold",12); c.drawString(m,y,"Capteurs"); y-=18; c.setFont("Helvetica",10)
        for s in sensors:
            line(f"{s.name} [{s.kind}] {s.target} → {s.result.status} ({s.result.latency_ms:.0f} ms) ok={s.ok_count} fail={s.fail_count}")
        c.showPage(); c.save()

# ======================== RGPD ==========================================
def load_consent() -> Optional[dict]:
    try:
        if os.path.exists(CONSENT_FILE): return json.load(open(CONSENT_FILE,"r",encoding="utf-8"))
    except Exception: logger.exception("load_consent failed")
    return None

def save_consent(name: str, organization: str, email: str) -> dict:
    data={"name":name.strip(),"organization":organization.strip(),"email":email.strip(),
          "date":_dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    try: json.dump(data, open(CONSENT_FILE,"w",encoding="utf-8"), indent=2, ensure_ascii=False)
    except Exception: logger.exception("save_consent failed")
    return data

def show_gdpr_signature(root: 'tk.Tk') -> dict:
    top=tk.Toplevel(root); top.title("Conformité RGPD - Signature obligatoire"); top.geometry("900x660"); Theme.apply(top); top.grab_set()
    frm=ttk.Frame(top); frm.pack(fill=tk.BOTH,expand=True,padx=12,pady=12)
    ttk.Label(frm,text="NetMon Pro - Notice RGPD",font=Theme.FONTS['title']).pack(pady=8)
    text=scrolledtext.ScrolledText(frm,height=14,wrap=tk.WORD); text.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)
    text.configure(foreground="#111827", background="#f0fdff", insertbackground=Theme.COLORS['accent'])
    notice=(
        "AVIS DE CONFORMITÉ RGPD\n\n"
        "Cette application (NetMon Pro) est destinée à la surveillance et au dépannage de réseaux.\n"
        "- Traitement local (aucune donnée envoyée à des tiers).\n"
        "- Les captures/sniffers et scans nécessitent des droits élevés et Npcap/libpcap.\n"
        "- Utilisation autorisée uniquement sur des réseaux dont vous avez l’autorisation.\n"
        "- L'auteur (Chaouki Boussayri) décline toute responsabilité en cas d’usage abusif.\n\n"
        "En signant, vous confirmez :\n"
        "1) Utiliser l'outil uniquement sur des réseaux autorisés.\n"
        "2) Comprendre vos obligations RGPD et légales.\n"
        "3) Assumer l’entière responsabilité de l’usage de cet outil."
    )
    text.insert(tk.END,notice); text.configure(state=tk.DISABLED)
    form=ttk.Labelframe(frm,text="Signature"); form.pack(fill=tk.X,padx=6,pady=6)
    row1=ttk.Frame(form); row1.pack(fill=tk.X,padx=6,pady=3)
    lbl_name=ttk.Label(row1,text="Nom et prénom *:",foreground=Theme.COLORS['rgpd_required']); lbl_name.pack(side=tk.LEFT)
    v_name=tk.StringVar(); ttk.Entry(row1,textvariable=v_name,width=45).pack(side=tk.LEFT,padx=6)
    row2=ttk.Frame(form); row2.pack(fill=tk.X,padx=6,pady=3)
    ttk.Label(row2,text="Organisation (optionnel):",foreground=Theme.COLORS['rgpd_label']).pack(side=tk.LEFT)
    v_org=tk.StringVar(); ttk.Entry(row2,textvariable=v_org,width=45).pack(side=tk.LEFT,padx=6)
    row3=ttk.Frame(form); row3.pack(fill=tk.X,padx=6,pady=3)
    ttk.Label(row3,text="Email (optionnel):",foreground=Theme.COLORS['rgpd_label']).pack(side=tk.LEFT)
    v_email=tk.StringVar(); ttk.Entry(row3,textvariable=v_email,width=45).pack(side=tk.LEFT,padx=6)
    ttk.Label(form,text="* Champs obligatoires",foreground=Theme.COLORS['rgpd_hint']).pack(anchor="w",padx=6,pady=4)
    v_accept=tk.BooleanVar(value=False)
    ttk.Checkbutton(form,text="Je confirme avoir lu et j'accepte les conditions ci-dessus.",variable=v_accept).pack(anchor="w",padx=6,pady=6)
    consent_data={}
    def on_sign():
        name=v_name.get().strip()
        if not name or not v_accept.get():
            lbl_name.configure(foreground=Theme.COLORS['err']); tk.messagebox.showwarning("RGPD","Renseignez votre nom et cochez la case."); return
        nonlocal consent_data; consent_data=save_consent(name,v_org.get(),v_email.get()); top.destroy()
    ttk.Button(frm,text="Signer et continuer",command=on_sign).pack(anchor="e",padx=6,pady=8)
    top.wait_window(); return consent_data

# ======================== PROFILS & ALERTES ==============================
DEFAULT_PROFILE = {"alert_cpu": 90,"alert_mem": 90,"alert_down_kb": 10_000,"alert_up_kb": 5_000,"known_devices": [],"sensors": []}
def load_profile() -> dict:
    try:
        if os.path.exists(PROFILE_PATH):
            prof=json.load(open(PROFILE_PATH,"r",encoding="utf-8"))
            for k,v in DEFAULT_PROFILE.items(): 
                if k not in prof: prof[k]=v
            return prof
    except Exception: logger.exception("load_profile")
    return DEFAULT_PROFILE.copy()
def save_profile(prof: dict):
    try: json.dump(prof, open(PROFILE_PATH,"w",encoding="utf-8"), indent=2, ensure_ascii=False)
    except Exception: logger.exception("save_profile")

# ======================== APPLICATION ===================================
class NetMonProApp:
    def __init__(self, root: 'tk.Tk', consent: dict):
        self.root=root; self.root.title(f"{APP_NAME} v{VERSION} — Enterprise"); self.root.geometry("1680x1020"); Theme.apply(root)
        self.consent=consent
        self.profile=load_profile()
        self.bandwidth=BandwidthMonitor(); self.scanner=NetworkScanner(); self.sniffer=PacketSniffer()
        self.supervisor=Supervisor(); self.supervisor.start()
        self.reporter=ReportBuilder()
        self.open_ports_by_host={}; self.vulns_by_host={}; self.last_devices=[]
        self._menu(); self._statusbar()
        self.nb=ttk.Notebook(self.root); self.nb.pack(fill=tk.BOTH,expand=True,padx=10,pady=10)
        self._tab_dashboard(); self._tab_interfaces(); self._tab_perf(); self._tab_devices_map()
        self._tab_connections(); self._tab_ports(); self._tab_ping(); self._tab_sniffer()
        self._tab_security(); self._tab_vuln(); self._tab_supervision()
        self._tab_maintenance(); self._tab_maintenance_adv()
        self._tab_inventory_logs(); self._tab_reports(); self._tab_profiles_alerts(); self._tab_options()
        self.bandwidth.start(); self._tick_dashboard(); self._tick_perf_plot(); self._tick_sniffer(); self._tick_supervision(); self._tick_alerts()

    # --- Menu & Status ---
    def _menu(self):
        m=tk.Menu(self.root)
        f=tk.Menu(m,tearoff=0); f.add_command(label="Exporter l'onglet",command=self.export_current_tab); f.add_separator(); f.add_command(label="Quitter",command=self.root.quit); m.add_cascade(label="Fichier",menu=f)
        tools=tk.Menu(m,tearoff=0); tools.add_command(label="Rafraîchir statut pcap",command=self._refresh_pcap_action); tools.add_command(label="Créer un point de restauration",command=self._create_restore_point); m.add_cascade(label="Outils",menu=tools)
        h=tk.Menu(m,tearoff=0); h.add_command(label="À propos",command=self.show_about); m.add_cascade(label="Aide",menu=h)
        self.root.config(menu=m)
    def _statusbar(self):
        bar=ttk.Frame(self.root); bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status=tk.StringVar(value=f"Prêt | {self.consent.get('name','?')} | Admin={is_admin()} | winget={bool(winget_path())} choco={has_command('choco')}")
        ttk.Label(bar, textvariable=self.status).pack(side=tk.LEFT, padx=8); ttk.Label(bar, text=f"Journal: {LOG_PATH}").pack(side=tk.RIGHT, padx=8)

    # --- Tabs ---
    def _tab_dashboard(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Tableau de bord")
        lf=ttk.Labelframe(frame,text="Résumé système"); lf.pack(fill=tk.X,padx=6,pady=6)
        self.cpu_var=tk.StringVar(); self.mem_var=tk.StringVar(); self.net_var=tk.StringVar()
        ttk.Label(lf,text="CPU:").pack(side=tk.LEFT,padx=6); ttk.Label(lf,textvariable=self.cpu_var).pack(side=tk.LEFT,padx=6)
        ttk.Label(lf,text="Mémoire:").pack(side=tk.LEFT,padx=6); ttk.Label(lf,textvariable=self.mem_var).pack(side=tk.LEFT,padx=6)
        ttk.Label(lf,text="Réseau:").pack(side=tk.LEFT,padx=6); ttk.Label(lf,textvariable=self.net_var).pack(side=tk.LEFT,padx=6)
        lf2=ttk.Labelframe(frame,text="Journal"); lf2.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)
        self.log=scrolledtext.ScrolledText(lf2,height=10); self.log.pack(fill=tk.BOTH,expand=True,padx=6,pady=6); self._log("Application démarrée.")
    def _tab_interfaces(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Interfaces")
        ttk.Button(frame,text="Actualiser",command=self._refresh_interfaces).pack(anchor="w",padx=6,pady=6)
        self.interfaces_text=scrolledtext.ScrolledText(frame); self.interfaces_text.pack(fill=tk.BOTH,expand=True,padx=6,pady=6); self._refresh_interfaces()
    def _tab_perf(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Performances")
        fig=Figure(figsize=(8.8,5.4),dpi=100); self.ax_cpu=fig.add_subplot(311); self.ax_mem=fig.add_subplot(312); self.ax_bw=fig.add_subplot(313)
        self.ax_cpu.set_title("CPU (%)"); self.ax_mem.set_title("Mémoire (%)"); self.ax_bw.set_title("Bande passante (KB/s)")
        self.cpu_hist=[]; self.mem_hist=[]; self.down_hist=[]; self.up_hist=[]; self.t_hist=[]
        self.canvas_perf=FigureCanvasTkAgg(fig,master=frame); self.canvas_perf.get_tk_widget().pack(fill=tk.BOTH,expand=True,padx=6,pady=6)
    def _tab_devices_map(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Cartographie")
        ctl=ttk.Frame(frame); ctl.pack(fill=tk.X,padx=6,pady=6); ttk.Button(ctl,text="Scanner le réseau",command=self._scan_and_draw).pack(side=tk.LEFT)
        area=ttk.Labelframe(frame,text="Topologie détectée"); area.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)
        fig=Figure(figsize=(7.8,5.8),dpi=100); self.ax_map=fig.add_subplot(111); self.canvas_map=FigureCanvasTkAgg(fig,master=area); self.canvas_map.get_tk_widget().pack(fill=tk.BOTH,expand=True,padx=6,pady=6)
    def _tab_connections(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Connexions")
        ttk.Button(frame,text="Actualiser",command=self._refresh_connections).pack(anchor="w",padx=6,pady=6)
        self.conn_text=scrolledtext.ScrolledText(frame); self.conn_text.pack(fill=tk.BOTH,expand=True,padx=6,pady=6); self._refresh_connections()
    def _tab_ports(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Ports")
        ctl=ttk.Frame(frame); ctl.pack(fill=tk.X,padx=6,pady=6)
        ttk.Label(ctl,text="Hôte:").pack(side=tk.LEFT,padx=4); self.port_host=tk.StringVar(value="127.0.0.1"); ttk.Entry(ctl,textvariable=self.port_host,width=24).pack(side=tk.LEFT)
        ttk.Button(ctl,text="Scanner",command=self._scan_ports_btn).pack(side=tk.LEFT,padx=4)
        self.ports_text=scrolledtext.ScrolledText(frame); self.ports_text.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)
    def _tab_ping(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Ping/Traceroute")
        ctl=ttk.Frame(frame); ctl.pack(fill=tk.X,padx=6,pady=6)
        ttk.Label(ctl,text="Hôte:").pack(side=tk.LEFT,padx=4); self.ping_host=tk.StringVar(value="8.8.8.8"); ttk.Entry(ctl,textvariable=self.ping_host,width=24).pack(side=tk.LEFT)
        ttk.Button(ctl,text="Ping",command=self._run_ping).pack(side=tk.LEFT,padx=4)
        ttk.Button(ctl,text="Traceroute",command=self._run_traceroute).pack(side=tk.LEFT,padx=4)
        self.ping_text=scrolledtext.ScrolledText(frame); self.ping_text.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)
    def _tab_sniffer(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Sniffer")
        ctl=ttk.Frame(frame); ctl.pack(fill=tk.X,padx=6,pady=6)
        self.sniff_iface=tk.StringVar(value=""); self.sniff_bpf=tk.StringVar(value="")
        ttk.Label(ctl,text="Interface (opt):").pack(side=tk.LEFT,padx=4); ttk.Entry(ctl,textvariable=self.sniff_iface,width=18).pack(side=tk.LEFT)
        ttk.Label(ctl,text="Filtre BPF (opt):").pack(side=tk.LEFT,padx=4); ttk.Entry(ctl,textvariable=self.sniff_bpf,width=25).pack(side=tk.LEFT)
        ttk.Button(ctl,text="Démarrer",command=self._start_sniffer).pack(side=tk.LEFT,padx=4); ttk.Button(ctl,text="Arrêter",command=self._stop_sniffer).pack(side=tk.LEFT,padx=4)
        self.sniff_text=scrolledtext.ScrolledText(frame,height=16); self.sniff_text.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)
    def _tab_security(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Sécurité (Ports)")
        ctl=ttk.Frame(frame); ctl.pack(fill=tk.X,padx=6,pady=6)
        ttk.Label(ctl,text="Hôte:").pack(side=tk.LEFT,padx=4); self.sec_host=tk.StringVar(value="127.0.0.1"); ttk.Entry(ctl,textvariable=self.sec_host,width=24).pack(side=tk.LEFT)
        ttk.Button(ctl,text="Analyser",command=self._security_analyze).pack(side=tk.LEFT,padx=4)
        self.sec_text=scrolledtext.ScrolledText(frame); self.sec_text.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)
    def _tab_vuln(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Vulnérabilités")
        ctl=ttk.Frame(frame); ctl.pack(fill=tk.X,padx=6,pady=6)
        ttk.Label(ctl,text="Cible (hôte/URL/dir):").pack(side=tk.LEFT,padx=4); self.vuln_target=tk.StringVar(value="127.0.0.1")
        ttk.Entry(ctl,textvariable=self.vuln_target,width=40).pack(side=tk.LEFT)
        ttk.Button(ctl,text="Nmap --script vuln",command=self._vuln_nmap).pack(side=tk.LEFT,padx=4)
        ttk.Button(ctl,text="Nuclei",command=self._vuln_nuclei).pack(side=tk.LEFT,padx=4)
        ttk.Button(ctl,text="Nikto",command=self._vuln_nikto).pack(side=tk.LEFT,padx=4)
        ttk.Button(ctl,text="sqlmap",command=self._vuln_sqlmap).pack(side=tk.LEFT,padx=4)
        ttk.Button(ctl,text="Trivy/Grype",command=self._vuln_trivy_grype).pack(side=tk.LEFT,padx=4)
        self.vuln_text=scrolledtext.ScrolledText(frame,height=20); self.vuln_text.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)
    def _tab_supervision(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Supervision (Capteurs)")
        ctl=ttk.Frame(frame); ctl.pack(fill=tk.X,padx=6,pady=6)
        self.sensor_kind=tk.StringVar(value="PING"); self.sensor_name=tk.StringVar(value="Host ping"); self.sensor_target=tk.StringVar(value="8.8.8.8")
        self.sensor_extra=tk.StringVar(value=""); self.sensor_interval=tk.IntVar(value=60)
        ttk.Label(ctl,text="Type:").pack(side=tk.LEFT); ttk.Combobox(ctl,textvariable=self.sensor_kind,values=["PING","PORT","HTTP","SNMP"],width=8,state="readonly").pack(side=tk.LEFT,padx=4)
        ttk.Label(ctl,text="Nom:").pack(side=tk.LEFT); ttk.Entry(ctl,textvariable=self.sensor_name,width=16).pack(side=tk.LEFT,padx=4)
        ttk.Label(ctl,text="Cible:").pack(side=tk.LEFT); ttk.Entry(ctl,textvariable=self.sensor_target,width=18).pack(side=tk.LEFT,padx=4)
        ttk.Label(ctl,text="Extra (port/community[/oid]):").pack(side=tk.LEFT); ttk.Entry(ctl,textvariable=self.sensor_extra,width=22).pack(side=tk.LEFT,padx=4)
        ttk.Label(ctl,text="Intervalle(s):").pack(side=tk.LEFT); ttk.Entry(ctl,textvariable=self.sensor_interval,width=6).pack(side=tk.LEFT,padx=4)
        ttk.Button(ctl,text="Ajouter",command=self._sensor_add).pack(side=tk.LEFT,padx=4)
        ttk.Button(ctl,text="Supprimer sélection",command=self._sensor_del).pack(side=tk.LEFT,padx=4)
        cols=("name","kind","target","status","latency","ok","fail")
        self.tree_s=ttk.Treeview(frame,columns=cols,show="headings",selectmode="extended")
        for c,w in zip(cols,(220,70,320,90,80,60,60)):
            self.tree_s.heading(c,text=c.capitalize()); self.tree_s.column(c,width=w,anchor="w")
        self.tree_s.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)

    # -------- Maintenance Basique --------
    def _tab_maintenance(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Maintenance Windows (Basique)")
        grid=ttk.Frame(frame); grid.pack(fill=tk.X,padx=8,pady=6)
        ttk.Label(grid,text="Intégrité & Image", foreground=Theme.COLORS['section']).grid(row=0,column=0,sticky="w",padx=4,pady=(4,2))
        ttk.Button(grid,text="SFC /SCANNOW",command=self._win_sfc).grid(row=1,column=0,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="DISM RestoreHealth",command=lambda:self._run_dism("RestoreHealth")).grid(row=1,column=1,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="AnalyzeComponentStore",command=lambda:self._run_dism("AnalyzeComponentStore")).grid(row=1,column=2,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="StartComponentCleanup (+ResetBase)",command=self._dism_cleanup).grid(row=1,column=3,padx=4,pady=4,sticky="w")
        ttk.Label(grid,text="Réseau", foreground=Theme.COLORS['section']).grid(row=2,column=0,sticky="w",padx=4,pady=(12,2))
        ttk.Button(grid,text="Reset Winsock/TCP-IP/IPv6",command=self._net_reset).grid(row=3,column=0,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="Flush DNS + DHCP renew",command=self._dns_dhcp).grid(row=3,column=1,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="ARP & NBTSTAT (refresh)",command=self._arp_nbt).grid(row=3,column=2,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="Redémarrer adaptateurs",command=self._restart_adapters).grid(row=3,column=3,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="Pare-feu: Reset",command=self._fw_reset).grid(row=3,column=4,padx=4,pady=4,sticky="w")
        ttk.Label(grid,text="Windows Update", foreground=Theme.COLORS['section']).grid(row=4,column=0,sticky="w",padx=4,pady=(12,2))
        ttk.Button(grid,text="Reset composants WU",command=self._wu_reset).grid(row=5,column=0,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="Reset proxy WinHTTP",command=self._winhttp_reset).grid(row=5,column=1,padx=4,pady=4,sticky="w")
        ttk.Label(grid,text="Stockage", foreground=Theme.COLORS['section']).grid(row=6,column=0,sticky="w",padx=4,pady=(12,2))
        ttk.Button(grid,text="CHKDSK (en ligne /scan)",command=self._chkdsk_scan).grid(row=7,column=0,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="Planifier CHKDSK /F (C:)",command=self._chkdsk_schedule).grid(row=7,column=1,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="Afficher dernier log CHKDSK",command=self._chkdsk_log).grid(row=7,column=2,padx=4,pady=4,sticky="w")
        ttk.Label(grid,text="Sécurité / Système", foreground=Theme.COLORS['section']).grid(row=8,column=0,sticky="w",padx=4,pady=(12,2))
        ttk.Button(grid,text="Defender — Scan rapide",command=lambda:self._defender_scan(quick=True)).grid(row=9,column=0,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="Defender — Scan complet",command=lambda:self._defender_scan(quick=False)).grid(row=9,column=1,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="Créer point de restauration",command=self._create_restore_point).grid(row=9,column=2,padx=4,pady=4,sticky="w")
        ttk.Label(grid,text="Impression", foreground=Theme.COLORS['section']).grid(row=10,column=0,sticky="w",padx=4,pady=(12,2))
        ttk.Button(grid,text="Nettoyer file d’attente (Spooler)",command=self._spooler_fix).grid(row=11,column=0,padx=4,pady=4,sticky="w")
        self.maint_text=scrolledtext.ScrolledText(frame,height=16); self.maint_text.pack(fill=tk.BOTH,expand=True,padx=8,pady=6)

    def _tab_maintenance_adv(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Maintenance Windows (Avancée)")
        grid=ttk.Frame(frame); grid.pack(fill=tk.X,padx=8,pady=6)
        ttk.Label(grid,text="Démarrage", foreground=Theme.COLORS['section']).grid(row=0,column=0,sticky="w",padx=4,pady=(4,2))
        ttk.Button(grid,text="Basculer en mode sans échec (minimal)",command=self._safe_mode_on).grid(row=1,column=0,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="Désactiver mode sans échec",command=self._safe_mode_off).grid(row=1,column=1,padx=4,pady=4,sticky="w")
        ttk.Label(grid,text="DISM & SFC (offline)", foreground=Theme.COLORS['section']).grid(row=2,column=0,sticky="w",padx=4,pady=(12,2))
        ttk.Button(grid,text="DISM RestoreHealth (source...)",command=self._dism_with_source).grid(row=3,column=0,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="SFC offline (sélectionner volume)",command=self._sfc_offline).grid(row=3,column=1,padx=4,pady=4,sticky="w")
        ttk.Label(grid,text="Pare-feu", foreground=Theme.COLORS['section']).grid(row=4,column=0,sticky="w",padx=4,pady=(12,2))
        ttk.Button(grid,text="Sauvegarder règles",command=self._fw_backup).grid(row=5,column=0,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="Restaurer règles",command=self._fw_restore).grid(row=5,column=1,padx=4,pady=4,sticky="w")
        ttk.Label(grid,text="Divers", foreground=Theme.COLORS['section']).grid(row=6,column=0,sticky="w",padx=4,pady=(12,2))
        ttk.Button(grid,text="GPUpdate /force",command=lambda:self._run_and_log("gpupdate /force")).grid(row=7,column=0,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="Vider %TEMP%",command=self._clear_temp).grid(row=7,column=1,padx=4,pady=4,sticky="w")
        ttk.Button(grid,text="Ré-enregistrer Apps Store",command=self._store_repair).grid(row=7,column=2,padx=4,pady=4,sticky="w")
        self.maint_adv=scrolledtext.ScrolledText(frame,height=16); self.maint_adv.pack(fill=tk.BOTH,expand=True,padx=8,pady=6)

    def _tab_inventory_logs(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Inventaire & Journaux")
        ctl=ttk.Frame(frame); ctl.pack(fill=tk.X,padx=6,pady=6)
        ttk.Button(ctl,text="Liste logiciels (winget list)",command=self._inventory_apps).pack(side=tk.LEFT,padx=4)
        ttk.Button(ctl,text="Logs Système (50)",command=lambda:self._event_logs("System")).pack(side=tk.LEFT,padx=4)
        ttk.Button(ctl,text="Logs Application (50)",command=lambda:self._event_logs("Application")).pack(side=tk.LEFT,padx=4)
        self.inv_text=scrolledtext.ScrolledText(frame,height=20); self.inv_text.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)

    def _tab_reports(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Rapports")
        ttk.Button(frame,text="Générer PDF",command=self._generate_report).pack(anchor="w",padx=6,pady=6)
        self.rep_text=scrolledtext.ScrolledText(frame,height=8); self.rep_text.pack(fill=tk.BOTH,expand=True,padx=6,pady=6)

    def _tab_profiles_alerts(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Profils & Alertes")
        lf=ttk.Labelframe(frame,text="Seuils d'alerte"); lf.pack(fill=tk.X,padx=8,pady=6)
        self.v_cpu=tk.IntVar(value=self.profile["alert_cpu"]); self.v_mem=tk.IntVar(value=self.profile["alert_mem"])
        self.v_down=tk.IntVar(value=self.profile["alert_down_kb"]); self.v_up=tk.IntVar(value=self.profile["alert_up_kb"])
        ttk.Label(lf,text="CPU % >").grid(row=0,column=0,sticky="w",padx=6,pady=4); ttk.Entry(lf,textvariable=self.v_cpu,width=6).grid(row=0,column=1,sticky="w")
        ttk.Label(lf,text="Mémoire % >").grid(row=0,column=2,sticky="w",padx=6); ttk.Entry(lf,textvariable=self.v_mem,width=6).grid(row=0,column=3,sticky="w")
        ttk.Label(lf,text="Download KB/s >").grid(row=0,column=4,sticky="w",padx=6); ttk.Entry(lf,textvariable=self.v_down,width=8).grid(row=0,column=5,sticky="w")
        ttk.Label(lf,text="Upload KB/s >").grid(row=0,column=6,sticky="w",padx=6); ttk.Entry(lf,textvariable=self.v_up,width=8).grid(row=0,column=7,sticky="w")
        ttk.Button(lf,text="Enregistrer",command=self._save_alerts).grid(row=0,column=8,sticky="w",padx=8)
        lf2=ttk.Labelframe(frame,text="Profils"); lf2.pack(fill=tk.X,padx=8,pady=6)
        ttk.Button(lf2,text="Exporter profil",command=self._export_profile).pack(side=tk.LEFT,padx=4)
        ttk.Button(lf2,text="Importer profil",command=self._import_profile).pack(side=tk.LEFT,padx=4)
        self.prof_text=scrolledtext.ScrolledText(frame,height=12); self.prof_text.pack(fill=tk.BOTH,expand=True,padx=8,pady=6)
        self._set_text(self.prof_text, json.dumps(self.profile, indent=2, ensure_ascii=False))

    def _tab_options(self):
        frame=ttk.Frame(self.nb); self.nb.add(frame,text="Options (Outils)")
        top=ttk.Frame(frame); top.pack(fill=tk.X,padx=8,pady=6)
        ttk.Label(top,text="Gestionnaire:").pack(side=tk.LEFT); self.mgr_pref=tk.StringVar(value="auto")
        ttk.Radiobutton(top,text="Auto",variable=self.mgr_pref,value="auto").pack(side=tk.LEFT,padx=4)
        ttk.Radiobutton(top,text="winget",variable=self.mgr_pref,value="winget").pack(side=tk.LEFT,padx=4)
        ttk.Radiobutton(top,text="choco",variable=self.mgr_pref,value="choco").pack(side=tk.LEFT,padx=4)
        ttk.Label(top,text="Catégorie:").pack(side=tk.LEFT,padx=(18,6))
        self.cat_var=tk.StringVar(value="Toutes")
        self.cat_combo=ttk.Combobox(top,textvariable=self.cat_var,values=["Toutes","Réseau","Sécurité","DevOps","Utilitaires","Sysadmin","Bureautique/Dev","Multimédia","Supervision/Agents","Vulnérabilité","Dépannage/Disque"],state="readonly",width=20); self.cat_combo.pack(side=tk.LEFT)
        self.cat_combo.bind("<<ComboboxSelected>>", lambda e: self._refresh_catalog())
        ttk.Label(top,text="Recherche:").pack(side=tk.LEFT,padx=(18,6)); self.search_var=tk.StringVar()
        ent=ttk.Entry(top,textvariable=self.search_var,width=28); ent.pack(side=tk.LEFT); ent.bind("<KeyRelease>", lambda e: self._refresh_catalog())
        ttk.Button(top,text="Installer sélection",command=self._install_selected).pack(side=tk.RIGHT,padx=4)
        ttk.Button(top,text="Vérifier (sélection)",command=self._check_selected).pack(side=tk.RIGHT,padx=4)
        body=ttk.Frame(frame); body.pack(fill=tk.BOTH,expand=True,padx=8,pady=(2,8))
        cols=("name","category","winget","choco")
        self.tree=ttk.Treeview(body,columns=cols,show="headings",selectmode="extended")
        for c,w in zip(cols,(320,180,360,240)): self.tree.heading(c,text=c.capitalize()); self.tree.column(c,width=w,anchor="w")
        self.tree.pack(fill=tk.BOTH,expand=True,side=tk.LEFT); scroll=ttk.Scrollbar(body,orient="vertical",command=self.tree.yview); scroll.pack(side=tk.RIGHT,fill=tk.Y); self.tree.configure(yscrollcommand=scroll.set)
        bottom=ttk.Labelframe(frame,text="Sortie / Progression"); bottom.pack(fill=tk.BOTH,expand=True,padx=8,pady=6)
        self.progress=ttk.Progressbar(bottom,mode="determinate"); self.progress.pack(fill=tk.X,padx=8,pady=6)
        self.opt_output=scrolledtext.ScrolledText(bottom,height=10); self.opt_output.pack(fill=tk.BOTH,expand=True,padx=8,pady=6)
        extra=ttk.Frame(frame); extra.pack(fill=tk.X,padx=8,pady=(0,8))
        ttk.Label(extra,text="Fonctionnalités Windows :").pack(side=tk.LEFT,padx=(0,6))
        ttk.Button(extra,text="Activer OpenSSH Client",command=lambda:self._enable_windows_capability("OpenSSH.Client~~~~0.0.1.0")).pack(side=tk.LEFT,padx=4)
        ttk.Button(extra,text="Activer OpenSSH Server",command=lambda:self._enable_windows_capability("OpenSSH.Server~~~~0.0.1.0")).pack(side=tk.LEFT,padx=4)
        ttk.Button(extra,text="Installer Npcap (site officiel)",command=self._install_npcap_official_btn).pack(side=tk.LEFT,padx=12)
        ttk.Button(extra,text="Rafraîchir statut pcap",command=self._refresh_pcap_action).pack(side=tk.LEFT,padx=4)

        # Catalogue étendu
        self.catalog=[
            # Réseau
            ("Wireshark","Réseau","WiresharkFoundation.Wireshark","wireshark"),
            ("Nmap","Réseau","Insecure.Nmap","nmap"),
            ("masscan","Réseau","","masscan"),
            ("OpenVPN","Réseau","OpenVPNTechnologies.OpenVPN","openvpn"),
            ("WireGuard","Réseau","WireGuard.WireGuard","wireguard"),
            ("OpenConnect GUI","Réseau","OpenConnect.openconnect-gui","openconnect-gui"),
            ("Gpg4win (GnuPG)","Réseau","GnuPG.Gpg4win","gpg4win"),
            ("OpenSSL","Réseau","ShiningLight.OpenSSL","openssl.light"),
            ("curl","Réseau","","curl"),
            ("wget","Réseau","GnuWin32.Wget","wget"),
            ("iperf3","Réseau","ar51an.iPerf3","iperf3"),
            ("WinMTR","Réseau","","winmtr"),
            ("tcping","Réseau","","tcping"),
            # Vulnérabilité
            ("OWASP ZAP","Vulnérabilité","ZAP.ZAP",""),
            ("ProjectDiscovery Nuclei","Vulnérabilité","ProjectDiscovery.Nuclei",""),
            ("ProjectDiscovery httpx","Vulnérabilité","ProjectDiscovery.HTTPX",""),
            ("ProjectDiscovery subfinder","Vulnérabilité","ProjectDiscovery.Subfinder",""),
            ("sqlmap","Vulnérabilité","","sqlmap"),
            ("Nikto","Vulnérabilité","","nikto"),
            ("YARA","Vulnérabilité","","yara"),
            ("Gitleaks","Vulnérabilité","GitTools.Gitleaks","gitleaks"),
            ("Trivy (containers)","Vulnérabilité","AquaSecurity.Trivy",""),
            ("Grype (containers)","Vulnérabilité","Anchore.Grype",""),
            # Supervision/Agents
            ("Zabbix Agent","Supervision/Agents","Zabbix.ZabbixAgent",""),
            ("PRTG Desktop","Supervision/Agents","Paessler.PRTGDesktop",""),
            ("Grafana Agent","Supervision/Agents","Grafana.Labs.Agent",""),
            ("Prometheus","Supervision/Agents","Prometheus.Prometheus","prometheus"),
            # Dépannage/Disque
            ("CrystalDiskInfo","Dépannage/Disque","CrystalDewWorld.CrystalDiskInfo",""),
            ("CrystalDiskMark","Dépannage/Disque","CrystalDewWorld.CrystalDiskMark",""),
            ("DISM++","Dépannage/Disque","ChuyuTeam.DISM++",""),
            # DevOps / outils généraux
            ("Git","DevOps","Git.Git","git"),
            ("GitHub CLI","DevOps","GitHub.cli","github-cli"),
            ("Python 3","DevOps","Python.Python.3","python"),
            ("Node.js LTS","DevOps","OpenJS.NodeJS.LTS","nodejs-lts"),
            ("Go","DevOps","GoLang.Go","golang"),
            ("Rust (rustup)","DevOps","Rustlang.Rustup","rust"),
            ("CMake","DevOps","Kitware.CMake","cmake"),
            ("MSYS2","DevOps","MSYS2.MSYS2","msys2"),
            ("OpenJDK Temurin 17","DevOps","EclipseAdoptium.Temurin.17.JDK","temurin17"),
            ("kubectl","DevOps","Kubernetes.kubectl","kubernetes-cli"),
            ("Helm","DevOps","Helm.Helm","kubernetes-helm"),
            ("Minikube","DevOps","Kubernetes.minikube","minikube"),
            # Bureautique/Dev
            ("Visual Studio Code","Bureautique/Dev","Microsoft.VisualStudioCode","vscode"),
            ("VSCodium","Bureautique/Dev","VSCodium.VSCodium","vscodium"),
            ("Notepad++","Bureautique/Dev","Notepad++.Notepad++","notepadplusplus"),
            ("LibreOffice","Bureautique/Dev","TheDocumentFoundation.LibreOffice","libreoffice-fresh"),
            ("GIMP","Bureautique/Dev","GIMP.GIMP","gimp"),
            ("Inkscape","Bureautique/Dev","Inkscape.Inkscape","inkscape"),
            ("Firefox","Bureautique/Dev","Mozilla.Firefox","firefox"),
            # Utilitaires / Sysadmin / Multimédia
            ("7-Zip","Utilitaires","7zip.7zip","7zip"),
            ("Sysinternals Suite","Utilitaires","Microsoft.Sysinternals","sysinternals"),
            ("NirLauncher (suite NirSoft)","Utilitaires","", "nirlauncher"),
            ("Everything","Utilitaires","voidtools.Everything","everything"),
            ("Process Hacker","Utilitaires","ProcessHacker.ProcessHacker","processhacker"),
            ("FFmpeg","Utilitaires","Gyan.FFmpeg","ffmpeg"),
            ("ShareX","Utilitaires","ShareX.ShareX","sharex"),
            ("Greenshot","Utilitaires","Greenshot.Greenshot","greenshot"),
            ("Npcap","Sysadmin","Nmap.Npcap","npcap"),
            ("Windows ADK","Sysadmin","Microsoft.WindowsADK",""),
            ("Windows ADK WinPE add-on","Sysadmin","Microsoft.WindowsADK.WinPEAddons",""),
            ("Windows Terminal","Sysadmin","Microsoft.WindowsTerminal",""),
            ("Rufus","Sysadmin","Rufus.Rufus",""),
            ("Ventoy","Sysadmin","Ventoy.Ventoy",""),
            ("VirtualBox","Sysadmin","Oracle.VirtualBox","virtualbox"),
            ("VLC","Multimédia","VideoLAN.VLC","vlc"),
            ("OBS Studio","Multimédia","OBSProject.OBSStudio","obs-studio"),
            ("HandBrake","Multimédia","HandBrake.HandBrake","handbrake"),
            ("Audacity","Multimédia","Audacity.Audacity","audacity"),
            ("HWiNFO","Utilitaires","REALiX.HWiNFO",""),
            ("WinDbg","Utilitaires","Microsoft.WinDbg",""),
        ]
        self._refresh_catalog()

    # ===================== Boucles périodiques =====================
    def _tick_dashboard(self):
        cpu=psutil.cpu_percent(); mem=psutil.virtual_memory().percent
        self.cpu_var.set(f"{cpu:.1f}%"); self.mem_var.set(f"{mem:.1f}%")
        try: socket.create_connection(("8.8.8.8",53),timeout=1.5).close(); self.net_var.set("Internet OK")
        except Exception: self.net_var.set("Pas d'Internet")
        self.root.after(2000,self._tick_dashboard)
    def _tick_perf_plot(self):
        cpu=psutil.cpu_percent(); mem=psutil.virtual_memory().percent; down,up=self.bandwidth.speeds
        down_kb=down/1024.0; up_kb=up/1024.0
        if len(getattr(self,"t_hist",[]))>=60: self.t_hist.pop(0); self.cpu_hist.pop(0); self.mem_hist.pop(0); self.down_hist.pop(0); self.up_hist.pop(0)
        self.t_hist.append(_dt.datetime.now().strftime("%H:%M:%S")); self.cpu_hist.append(cpu); self.mem_hist.append(mem); self.down_hist.append(down_kb); self.up_hist.append(up_kb)
        self.ax_cpu.clear(); self.ax_mem.clear(); self.ax_bw.clear()
        self.ax_cpu.set_title("CPU (%)"); self.ax_mem.set_title("Mémoire (%)"); self.ax_bw.set_title("Bande passante (KB/s)")
        self.ax_cpu.plot(self.cpu_hist,linewidth=1.6); self.ax_mem.plot(self.mem_hist,linewidth=1.6)
        self.ax_bw.plot(self.down_hist,linewidth=1.6,label="Down"); self.ax_bw.plot(self.up_hist,linewidth=1.6,label="Up"); self.ax_bw.legend(loc="upper left")
        self.canvas_perf.draw(); self.root.after(1000,self._tick_perf_plot)
    def _tick_sniffer(self):
        try:
            while True: line=self.sniffer.queue.get_nowait(); self._append(self.sniff_text,line+"\n")
        except queue.Empty: pass
        self.root.after(300,self._tick_sniffer)
    def _tick_supervision(self):
        for iid in self.tree_s.get_children(): self.tree_s.delete(iid)
        for s in self.supervisor.sensors:
            self.tree_s.insert("", "end", values=(s.name,s.kind,s.target,s.result.status,f"{s.result.latency_ms:.0f}",s.ok_count,s.fail_count))
        self.root.after(1000,self._tick_supervision)
    def _tick_alerts(self):
        try:
            cpu=psutil.cpu_percent(); mem=psutil.virtual_memory().percent; down_kb=self.bandwidth.speeds[0]/1024.0; up_kb=self.bandwidth.speeds[1]/1024.0
            alerts=[]
            if cpu>self.profile["alert_cpu"]: alerts.append(f"CPU élevé : {cpu:.1f}%")
            if mem>self.profile["alert_mem"]: alerts.append(f"Mémoire élevée : {mem:.1f}%")
            if down_kb>self.profile["alert_down_kb"]: alerts.append(f"Download élevé : {down_kb:.0f} KB/s")
            if up_kb>self.profile["alert_up_kb"]: alerts.append(f"Upload élevé : {up_kb:.0f} KB/s")
            if self.last_devices:
                known=set(self.profile.get("known_devices",[])); current=set([ip for ip,_,_ in self.last_devices])
                new=current-known
                if new:
                    alerts.append("Nouveaux appareils : "+", ".join(sorted(new)))
                    self.profile["known_devices"]=sorted(current); save_profile(self.profile)
            if alerts: self._log(" | ".join(alerts))
        except Exception: pass
        self.root.after(2000,self._tick_alerts)

    # ===================== Actions réseau / sécurité =====================
    def _scan_and_draw(self):
        self.status.set("Scan réseau en cours..."); self._log("Début scan réseau.")
        def worker():
            try:
                self.scanner.scan_local(); self.last_devices=list(self.scanner.results)
                import networkx as nx
                G=self.scanner.build_graph(); self.ax_map.clear(); pos=nx.spring_layout(G,seed=42)
                labels={n:(G.nodes[n].get("label") or n) for n in G.nodes()}; nx.draw(G,pos=pos,ax=self.ax_map,with_labels=False,node_size=520); nx.draw_networkx_labels(G,pos=pos,labels=labels,ax=self.ax_map,font_size=8)
                self.canvas_map.draw(); self.status.set(f"Scan terminé. {len(self.last_devices)} hôtes.")
            except Exception as e: logger.exception("Scan/draw failed"); self._log(f"Erreur scan: {e}")
        threading.Thread(target=worker,daemon=True).start()
    def _refresh_interfaces(self):
        lines=[]; addrs=psutil.net_if_addrs(); stats=psutil.net_if_stats()
        for iface,lst in addrs.items():
            st=stats.get(iface); state="up" if (st and st.isup) else "down"; lines.append(f"{iface} ({state})")
            for a in lst:
                if a.family==socket.AF_INET: lines.append(f"  IPv4: {a.address}/{a.netmask}")
                elif a.family==socket.AF_INET6: lines.append(f"  IPv6: {a.address}")
                elif hasattr(psutil,'AF_LINK') and a.family==psutil.AF_LINK: lines.append(f"  MAC:  {a.address}")
            lines.append("")
        self._set_text(self.interfaces_text,"\n".join(lines))
    def _refresh_connections(self):
        out=[]
        try:
            conns=psutil.net_connections(kind='tcp')
            for c in conns:
                l=f"{getattr(c,'laddr','')}"; r=f"{getattr(c,'raddr','')}"; out.append(f"{c.status:<13} {l:<22} -> {r:<22} pid:{c.pid}")
        except Exception as e: out.append(f"Erreur: {e}")
        self._set_text(self.conn_text,"\n".join(out))
    def _scan_ports_btn(self):
        host=self.port_host.get().strip()
        if not host: tk.messagebox.showwarning("Scan","Indiquez un hôte."); return
        self.status.set(f"Scan de ports sur {host}...")
        def worker():
            common=[21,22,23,25,53,80,110,139,143,389,443,445,587,993,995,1433,1521,2049,2375,2376,3306,3389,5432,5672,5900,5985,5986,6379,8000,8080,8443,9000,9200,11211,27017]
            res=port_scan(host,common); self.open_ports_by_host[host]=res
            lines=[f"Résultats pour {host} :"]+[f"  {p}: {b}" for p,b in sorted(res.items())]
            if not res: lines.append("  Aucun port commun ouvert détecté.")
            self._set_text(self.ports_text,"\n".join(lines)); self.status.set("Scan ports terminé.")
        threading.Thread(target=worker,daemon=True).start()
    def _run_ping(self):
        target=self.ping_host.get().strip()
        if not target: tk.messagebox.showwarning("Ping","Entrer un hôte."); return
        self._set_text(self.ping_text,f"Test ping vers {target}...\n")
        def worker(): ok=ping(target,4,1.0); self._append(self.ping_text,f"Résultat: {'OK' if ok else 'Échec'}\n")
        threading.Thread(target=worker,daemon=True).start()
    def _run_traceroute(self):
        target=self.ping_host.get().strip()
        if not target: tk.messagebox.showwarning("Traceroute","Entrer un hôte."); return
        self._set_text(self.ping_text,f"Traceroute vers {target}...\n")
        def worker(): out=traceroute(target); self._append(self.ping_text,out+"\n")
        threading.Thread(target=worker,daemon=True).start()
    def _start_sniffer(self):
        iface=self.sniff_iface.get().strip() or None; bpf=self.sniff_bpf.get().strip() or None
        self._append(self.sniff_text,"[Sniffer] Démarrage...\n"); self.sniffer.start(iface=iface,bpf=bpf)
    def _stop_sniffer(self): self.sniffer.stop(); self._append(self.sniff_text,"[Sniffer] Arrêté.\n")
    def _security_analyze(self):
        host=self.sec_host.get().strip()
        if not host: tk.messagebox.showwarning("Sécurité","Indiquez un hôte."); return
        self.status.set(f"Analyse de sécurité {host}...")
        def worker():
            common=[21,22,23,25,53,80,110,139,143,389,443,445,587,993,995,1433,1521,2049,2375,2376,3306,3389,5432,5672,5900,5985,5986,6379,8000,8080,8443,9000,9200,11211,27017]
            res=port_scan(host,common); self.open_ports_by_host[host]=res; vulns=evaluate_vulns(res); self.vulns_by_host[host]=vulns
            lines=[f"[{host}] Ports ouverts:"]+([f"  - {p}: {b}" for p,b in sorted(res.items())] or ["  Aucun port commun ouvert."])+["Observations:",]+(["  - "+v for v in vulns] or ["  RAS selon règles basiques."])
            self._set_text(self.sec_text,"\n".join(lines)); self.status.set("Analyse sécurité terminée.")
        threading.Thread(target=worker,daemon=True).start()

    # ===================== Vuln tools (optionnels) =====================
    def _append_vuln(self,txt): self.vuln_text.configure(state=tk.NORMAL); self.vuln_text.insert(tk.END,txt); self.vuln_text.see(tk.END); self.vuln_text.configure(state=tk.DISABLED)
    def _vuln_nmap(self):
        target=self.vuln_target.get().strip()
        wp=winget_path()
        if not has_command("nmap") and not wp: tk.messagebox.showinfo("Nmap","Nmap non trouvé. Installez-le via Options."); return
        self._set_text(self.vuln_text,f"[Nmap vuln] {target}\n")
        def worker():
            try:
                cp=subprocess.run(["nmap","-sV","--script","vuln",target],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=900)
                self._append_vuln(cp.stdout or "")
            except Exception as e: self._append_vuln(f"Erreur Nmap: {e}\n")
        threading.Thread(target=worker,daemon=True).start()
    def _vuln_nuclei(self):
        target=self.vuln_target.get().strip()
        if not has_command("nuclei"): tk.messagebox.showinfo("Nuclei","Nuclei non trouvé. Installez-le via Options."); return
        self._set_text(self.vuln_text,f"[Nuclei] {target}\n")
        def worker():
            try:
                cp=subprocess.run(["nuclei","-u",target,"-silent"],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=900)
                self._append_vuln(cp.stdout or "")
            except Exception as e: self._append_vuln(f"Erreur Nuclei: {e}\n")
        threading.Thread(target=worker,daemon=True).start()
    def _vuln_nikto(self):
        target=self.vuln_target.get().strip()
        if not has_command("nikto"): tk.messagebox.showinfo("Nikto","Nikto non trouvé. Via Chocolatey : nikto."); return
        self._set_text(self.vuln_text,f"[Nikto] {target}\n")
        def worker():
            try:
                cp=subprocess.run(["nikto","-host",target],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=900)
                self._append_vuln(cp.stdout or "")
            except Exception as e: self._append_vuln(f"Erreur Nikto: {e}\n")
        threading.Thread(target=worker,daemon=True).start()
    def _vuln_sqlmap(self):
        target=self.vuln_target.get().strip()
        if not has_command("sqlmap"): tk.messagebox.showinfo("sqlmap","sqlmap non trouvé. Via Chocolatey : sqlmap."); return
        self._set_text(self.vuln_text,f"[sqlmap] {target}\n")
        def worker():
            try:
                cp=subprocess.run(["sqlmap","-u",target,"--batch","--level","1","--risk","1","--crawl","1","--smart"],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=900)
                self._append_vuln(cp.stdout or "")
            except Exception as e: self._append_vuln(f"Erreur sqlmap: {e}\n")
        threading.Thread(target=worker,daemon=True).start()
    def _vuln_trivy_grype(self):
        target=self.vuln_target.get().strip()
        self._set_text(self.vuln_text,f"[Trivy/Grype] scan {target}\n")
        def worker():
            if has_command("trivy"):
                try:
                    cp=subprocess.run(["trivy","fs",target,"--quiet"],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=900)
                    self._append_vuln("=== Trivy ===\n"+(cp.stdout or ""))
                except Exception as e: self._append_vuln(f"Erreur Trivy: {e}\n")
            else: self._append_vuln("Trivy non installé.\n")
            if has_command("grype"):
                try:
                    cp=subprocess.run(["grype",target],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=900)
                    self._append_vuln("=== Grype ===\n"+(cp.stdout or ""))
                except Exception as e: self._append_vuln(f"Erreur Grype: {e}\n")
            else: self._append_vuln("Grype non installé.\n")
        threading.Thread(target=worker,daemon=True).start()

    # ===================== Supervision =====================
    def _sensor_add(self):
        kind=self.sensor_kind.get(); name=self.sensor_name.get().strip() or f"{kind} sensor"; target=self.sensor_target.get().strip(); extra=self.sensor_extra.get().strip(); itv=max(5,int(self.sensor_interval.get() or 60))
        if not target: tk.messagebox.showwarning("Capteur","Cible requise."); return
        if kind=="PING": s=PingSensor(name,target,itv)
        elif kind=="PORT":
            try: port=int(extra or "80")
            except: tk.messagebox.showwarning("PORT","Indiquez un port (Extra)."); return
            host=target.split(":")[0]; s=PortSensor(name,host,port,itv)
        elif kind=="HTTP": s=HttpSensor(name,target,itv)
        elif kind=="SNMP":
            parts=extra.split("/") if extra else []
            community = parts[0] if parts else "public"
            oid = parts[1] if len(parts)>1 else "1.3.6.1.2.1.1.1.0"
            s=SNMPSensor(name,target,community,oid,itv)
        else: return
        self.supervisor.add(s)
        self.profile["sensors"].append({"kind":kind,"name":name,"target":target,"extra":extra,"interval":itv})
        save_profile(self.profile)
        self._set_text(self.prof_text, json.dumps(self.profile, indent=2, ensure_ascii=False))
    def _sensor_del(self):
        sels=self.tree_s.selection()
        if not sels: return
        names=set(self.tree_s.item(iid,"values")[0] for iid in sels)
        self.supervisor.sensors=[s for s in self.supervisor.sensors if s.name not in names]
        self.profile["sensors"]=[s for s in self.profile["sensors"] if s.get("name") not in names]; save_profile(self.profile)
        self._set_text(self.prof_text, json.dumps(self.profile, indent=2, ensure_ascii=False))

    # ===================== Maintenance — Implémentations =====================
    def _append_maint(self,txt): self.maint_text.configure(state=tk.NORMAL); self.maint_text.insert(tk.END,txt); self.maint_text.see(tk.END); self.maint_text.configure(state=tk.DISABLED)
    def _append_maint_adv(self,txt): self.maint_adv.configure(state=tk.NORMAL); self.maint_adv.insert(tk.END,txt); self.maint_adv.see(tk.END); self.maint_adv.configure(state=tk.DISABLED)
    def _run_and_log(self, cmd: str, powershell: bool=False):
        try:
            if powershell: rc=run_ps_inline(cmd,elevated=True)
            else: rc=subprocess.call(cmd, shell=True)
            self._append_maint(f"→ Terminé (rc={rc}).\n")
        except Exception as e: self._append_maint(f"Erreur: {e}\n")

    # -- SFC / DISM (en ligne) --
    def _win_sfc(self):
        if not tk.messagebox.askyesno("SFC","Exécuter SFC /SCANNOW (peut être long) ?"): return
        self._append_maint("SFC /SCANNOW en cours...\n"); threading.Thread(target=lambda:self._run_and_log("sfc /scannow"),daemon=True).start()
    def _run_dism(self,mode:str):
        if mode=="AnalyzeComponentStore": cmd="Dism /Online /Cleanup-Image /AnalyzeComponentStore"
        elif mode=="RestoreHealth": cmd="Dism /Online /Cleanup-Image /RestoreHealth"
        else: cmd=f"Dism /Online /Cleanup-Image /{mode}"
        self._append_maint(cmd+"...\n"); threading.Thread(target=lambda:self._run_and_log(cmd),daemon=True).start()
    def _dism_cleanup(self):
        cmd="Dism /Online /Cleanup-Image /StartComponentCleanup /ResetBase"; self._append_maint(cmd+"...\n"); threading.Thread(target=lambda:self._run_and_log(cmd),daemon=True).start()

    # -- Réseau --
    def _net_reset(self):
        ps=("netsh winsock reset; netsh int ip reset; netsh int ipv6 reset; ipconfig /flushdns")
        if tk.messagebox.askyesno("Réseau","Réinitialiser Winsock/TCP/IP/IPv6 et vider DNS ? Nécessite redémarrage."):
            self._append_maint(ps+"\n"); threading.Thread(target=lambda:self._run_and_log(ps),daemon=True).start()
    def _dns_dhcp(self):
        ps="ipconfig /flushdns & ipconfig /release & ipconfig /renew"
        self._append_maint(ps+"\n"); threading.Thread(target=lambda:self._run_and_log(ps),daemon=True).start()
    def _arp_nbt(self):
        ps="arp -d * & nbtstat -R & nbtstat -RR"
        self._append_maint(ps+"\n"); threading.Thread(target=lambda:self._run_and_log(ps),daemon=True).start()
    def _restart_adapters(self):
        ps="Get-NetAdapter | ? Status -eq 'Up' | Restart-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue"
        self._append_maint("Redémarrage adaptateurs réseau...\n"); threading.Thread(target=lambda:self._run_and_log(ps,True),daemon=True).start()
    def _fw_reset(self):
        ps="netsh advfirewall reset"
        if tk.messagebox.askyesno("Pare-feu","Réinitialiser les règles du pare-feu ?"):
            self._append_maint(ps+"\n"); threading.Thread(target=lambda:self._run_and_log(ps),daemon=True).start()
    def _fw_backup(self):
        path=filedialog.asksaveasfilename(defaultextension=".wfw",filetypes=[("Pare-feu (.wfw)","*.wfw")],initialfile="firewall_backup.wfw")
        if not path: return
        ps=f'netsh advfirewall export "{path}"'
        self._append_maint_adv(f"Sauvegarde pare-feu vers {path}\n"); threading.Thread(target=lambda:self._run_and_log(ps),daemon=True).start()
    def _fw_restore(self):
        path=filedialog.askopenfilename(filetypes=[("Pare-feu (.wfw)","*.wfw")])
        if not path: return
        ps=f'netsh advfirewall import "{path}"'
        if tk.messagebox.askyesno("Pare-feu","Importer et écraser les règles actuelles ?"):
            self._append_maint_adv(f"Import pare-feu depuis {path}\n"); threading.Thread(target=lambda:self._run_and_log(ps),daemon=True).start()
    def _winhttp_reset(self):
        ps="netsh winhttp reset proxy"
        self._append_maint(ps+"\n"); threading.Thread(target=lambda:self._run_and_log(ps),daemon=True).start()

    # -- Windows Update --
    def _wu_reset(self):
        ps=("net stop bits; net stop wuauserv; net stop cryptSvc; net stop msiserver; "
            "rd /s /q %windir%\\SoftwareDistribution; rd /s /q %windir%\\System32\\catroot2; "
            "net start bits; net start wuauserv; net start cryptSvc; net start msiserver")
        if tk.messagebox.askyesno("Windows Update","Réinitialiser les composants Windows Update ?"):
            self._append_maint("Réinitialisation WU...\n"); threading.Thread(target=lambda:self._run_and_log(ps),daemon=True).start()

    # -- Stockage / CHKDSK --
    def _system_drive(self)->str: return os.getenv("SystemDrive","C:")
    def _chkdsk_scan(self):
        cmd=f"chkdsk {self._system_drive()} /scan"; self._append_maint(cmd+"...\n"); threading.Thread(target=lambda:self._run_and_log(cmd),daemon=True).start()
    def _chkdsk_schedule(self):
        cmd=f"chkdsk {self._system_drive()} /F /R"
        if tk.messagebox.askyesno("CHKDSK","Planifier une vérification /F /R au prochain redémarrage ?"):
            self._append_maint(cmd+" (planification)...\n"); threading.Thread(target=lambda:self._run_and_log(cmd),daemon=True).start()
    def _chkdsk_log(self):
        ps=("Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Microsoft-Windows-Wininit'} -MaxEvents 1 | Format-List TimeCreated, Message; "
            "Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='Chkdsk'} -MaxEvents 1 | Format-List TimeCreated, Message")
        self._append_maint("Lecture du dernier journal CHKDSK...\n")
        def run(): 
            try:
                cp=subprocess.run(["powershell","-NoProfile","-ExecutionPolicy","Bypass","-Command",ps],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=90)
                self._append_maint((cp.stdout or "")+"\n")
            except Exception as e: self._append_maint(f"Erreur Get-WinEvent: {e}\n")
        threading.Thread(target=run,daemon=True).start()

    # -- Sécurité / Defender & Restore Point --
    def _defender_path(self)->Optional[str]:
        candidates=[
            r"C:\Program Files\Windows Defender\MpCmdRun.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\Platform"
        ]
        for c in candidates:
            if os.path.isfile(c): return c
            if os.path.isdir(c):
                try:
                    vers=sorted([d for d in os.listdir(c) if re.match(r'^\d+\.\d+\.\d+\.\d+$',d)], reverse=True)
                    if vers:
                        p=os.path.join(c,vers[0],"MpCmdRun.exe")
                        if os.path.isfile(p): return p
                except Exception: pass
        return None
    def _defender_scan(self, quick=True):
        exe=self._defender_path()
        if not exe: self._append_maint("MpCmdRun introuvable.\n"); return
        args=f'"{exe}" -Scan -ScanType {"1" if quick else "2"}'
        self._append_maint(("Scan rapide" if quick else "Scan complet")+ " Defender...\n")
        threading.Thread(target=lambda:self._run_and_log(args),daemon=True).start()
    def _create_restore_point(self):
        ps='Checkpoint-Computer -Description "NetMonPro" -RestorePointType MODIFY_SETTINGS'
        self._append_maint("Création d’un point de restauration...\n")
        threading.Thread(target=lambda:self._run_and_log(ps,True),daemon=True).start()

    # -- Impression --
    def _spooler_fix(self):
        ps=("net stop spooler & del /Q /F %systemroot%\\System32\\spool\\PRINTERS\\* & net start spooler")
        self._append_maint("Nettoyage file d'attente d'impression...\n"); threading.Thread(target=lambda:self._run_and_log(ps),daemon=True).start()

    # -- Avancé : Safe Mode, DISM source, SFC offline, TEMP, Store --
    def _safe_mode_on(self):
        ps="bcdedit /set {default} safeboot minimal"
        if tk.messagebox.askyesno("Mode sans échec","Activer le mode sans échec (minimal) pour le prochain démarrage ?"):
            self._append_maint_adv(ps+"\n"); threading.Thread(target=lambda:self._run_and_log(ps),daemon=True).start()
    def _safe_mode_off(self):
        ps="bcdedit /deletevalue {default} safeboot"
        self._append_maint_adv(ps+"\n"); threading.Thread(target=lambda:self._run_and_log(ps),daemon=True).start()
    def _dism_with_source(self):
        path=filedialog.askdirectory(title="Sélectionner le dossier source (install.wim monté ou SxS)")
        if not path: return
        cmd=f'Dism /Online /Cleanup-Image /RestoreHealth /Source:"{path}" /LimitAccess'
        self._append_maint_adv(cmd+"\n"); threading.Thread(target=lambda:self._run_and_log(cmd),daemon=True).start()
    def _sfc_offline(self):
        drive=filedialog.askdirectory(title="Sélectionner le dossier Windows offline (ex: D:\\Windows)")
        if not drive: return
        root=os.path.splitdrive(drive)[0] or drive[:2]
        cmd=f'sfc /scannow /offbootdir={root}\\ /offwindir="{drive}"'
        self._append_maint_adv(cmd+"\n"); threading.Thread(target=lambda:self._run_and_log(cmd),daemon=True).start()
    def _clear_temp(self):
        ps='Remove-Item -Path "$env:TEMP\\*" -Recurse -Force -ErrorAction SilentlyContinue'
        self._append_maint_adv("Nettoyage %TEMP%...\n"); threading.Thread(target=lambda:self._run_and_log(ps,True),daemon=True).start()
    def _store_repair(self):
        ps="Get-AppxPackage -AllUsers|Foreach {Add-AppxPackage -DisableDevelopmentMode -Register \"$($_.InstallLocation)\\AppXManifest.xml\"}"
        if tk.messagebox.askyesno("Store","Ré-enregistrer les applications Store pour tous les utilisateurs ?"):
            self._append_maint_adv("Réparation Store...\n"); threading.Thread(target=lambda:self._run_and_log(ps,True),daemon=True).start()

    # ===================== Inventaire & Journaux =====================
    def _inventory_apps(self):
        self._set_text(self.inv_text,"Inventaire en cours...\n")
        def worker():
            out=""; wp=winget_path()
            if wp:
                try:
                    cp=subprocess.run([wp,"list"],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=180)
                    out=cp.stdout or ""
                except Exception as e: out=f"Erreur winget list: {e}"
            else:
                out="winget non disponible. Essayez l’onglet Options pour l’installer."
            self._set_text(self.inv_text,out)
        threading.Thread(target=worker,daemon=True).start()
    def _event_logs(self, logname:str):
        self._append(self.inv_text,f"--- Derniers événements: {logname} ---\n")
        def worker():
            ps=f"Get-WinEvent -LogName {logname} -MaxEvents 50 | Format-List -Property TimeCreated,Id,LevelDisplayName,ProviderName,Message"
            try:
                cp=subprocess.run(["powershell","-NoProfile","-ExecutionPolicy","Bypass","-Command",ps],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=120)
                self._append(self.inv_text,(cp.stdout or "")+"\n")
            except Exception as e:
                self._append(self.inv_text,f"Erreur Get-WinEvent: {e}\n")
        threading.Thread(target=worker,daemon=True).start()

    # ===================== Rapports =====================
    def _generate_report(self):
        path=filedialog.asksaveasfilename(defaultextension=".pdf",filetypes=[("PDF","*.pdf")],initialfile="netmon_report.pdf")
        if not path: return
        meta={"Utilisateur":self.consent.get("name","(inconnu)"),"Outil":f"NetMon Pro {VERSION}"}
        diags=[]
        try: socket.create_connection(("8.8.8.8",53),2).close(); diags.append("Internet: OK")
        except Exception: diags.append("Internet: KO")
        diags.append(f"CPU: {psutil.cpu_percent():.1f}%"); diags.append(f"RAM: {psutil.virtual_memory().percent:.1f}%")
        try:
            self.reporter.build_pdf(path,meta,self.last_devices,self.open_ports_by_host,self.vulns_by_host,diags,self.supervisor.sensors)
            self._append(self.rep_text,f"Rapport généré: {path}\n")
        except Exception as e:
            tk.messagebox.showerror("Rapport",f"Échec: {e}")

    # ===================== Profils & Alertes =====================
    def _save_alerts(self):
        self.profile["alert_cpu"]=int(self.v_cpu.get() or 90)
        self.profile["alert_mem"]=int(self.v_mem.get() or 90)
        self.profile["alert_down_kb"]=int(self.v_down.get() or 10000)
        self.profile["alert_up_kb"]=int(self.v_up.get() or 5000)
        save_profile(self.profile)
        self._set_text(self.prof_text, json.dumps(self.profile, indent=2, ensure_ascii=False))
        self._log("Seuils d’alerte mis à jour.")
    def _export_profile(self):
        path=filedialog.asksaveasfilename(defaultextension=".json",filetypes=[("JSON","*.json")],initialfile="netmon_profile.json")
        if not path: return
        try: json.dump(self.profile, open(path,"w",encoding="utf-8"), indent=2, ensure_ascii=False); self._log(f"Profil exporté : {path}")
        except Exception as e: tk.messagebox.showerror("Export profil", str(e))
    def _import_profile(self):
        path=filedialog.askopenfilename(filetypes=[("JSON","*.json")])
        if not path: return
        try:
            self.profile=json.load(open(path,"r",encoding="utf-8")); save_profile(self.profile)
            self.v_cpu.set(self.profile.get("alert_cpu",90)); self.v_mem.set(self.profile.get("alert_mem",90))
            self.v_down.set(self.profile.get("alert_down_kb",10000)); self.v_up.set(self.profile.get("alert_up_kb",5000))
            self._set_text(self.prof_text, json.dumps(self.profile, indent=2, ensure_ascii=False))
            self._log(f"Profil importé : {path}")
        except Exception as e: tk.messagebox.showerror("Import profil", str(e))

    # ===================== Options / Outils =====================
    def _refresh_catalog(self):
        for iid in self.tree.get_children(): self.tree.delete(iid)
        q=(self.search_var.get() or "").lower().strip(); cat=self.cat_var.get()
        for name,category,winget_id,choco_id in self.catalog:
            if cat!="Toutes" and category!=cat: continue
            if q and (q not in name.lower() and q not in (winget_id or "").lower() and q not in (choco_id or "").lower()): continue
            self.tree.insert("", "end", values=(name,category,winget_id,choco_id))
    def _append_opts(self,txt): self.opt_output.configure(state=tk.NORMAL); self.opt_output.insert(tk.END,txt); self.opt_output.see(tk.END); self.opt_output.configure(state=tk.DISABLED)
    def _install_selected(self):
        items=[self.tree.item(iid,"values") for iid in self.tree.selection()]
        if not items: tk.messagebox.showinfo("Installation","Sélectionnez au moins un outil."); return
        mgr=self.mgr_pref.get(); total=len(items); self.progress.configure(maximum=total,value=0); self._append_opts(f"--- Installation ({mgr}) ---\n")
        def worker():
            done=0
            for name,category,winget_id,choco_id in items:
                rc=1
                if mgr=="winget" or (mgr=="auto" and winget_id):
                    if winget_id:
                        wp=winget_path()
                        if wp: self._append_opts(f"[winget] {name}...\n"); rc=run_ps_inline(f'& "{wp}" install "{winget_id}" --silent --accept-package-agreements --accept-source-agreements',elevated=True)
                if rc!=0 and (mgr=="choco" or (mgr=="auto" and choco_id)):
                    if choco_id and not has_command("choco"): ensure_chocolatey()
                    if choco_id: self._append_opts(f"[choco] {name}...\n"); rc=run_ps_inline(f"choco install {choco_id} -y",elevated=True)
                self._append_opts(f"→ {name} terminé (rc={rc}).\n"); done+=1; self.progress.configure(value=done)
            self._append_opts("--- Fin ---\n")
        threading.Thread(target=worker,daemon=True).start()
    def _check_selected(self):
        items=[self.tree.item(iid,"values") for iid in self.tree.selection()]
        if not items: tk.messagebox.showinfo("Vérification","Sélectionnez au moins un outil."); return
        self._append_opts("--- Vérification ---\n")
        def worker():
            for name,category,winget_id,choco_id in items:
                if winget_id:
                    wp=winget_path()
                    if wp: rc=run_ps_inline(f'& "{wp}" show "{winget_id}"',elevated=False); self._append_opts(f"[winget] {name}: rc={rc}\n")
                if choco_id: rc=run_ps_inline(f"choco info {choco_id}",elevated=False); self._append_opts(f"[choco] {name}: rc={rc}\n")
            self._append_opts("--- Fin ---\n")
        threading.Thread(target=worker,daemon=True).start()
    def _enable_windows_capability(self,cap_name:str):
        if not is_windows(): tk.messagebox.showwarning("Fonctionnalité Windows","Non applicable."); return
        self._append_opts(f"[DISM] Activation {cap_name}...\n")
        def worker(): rc=run_ps_inline(f"Add-WindowsCapability -Online -Name {cap_name}",elevated=True); self._append_opts(f"→ rc={rc}\n")
        threading.Thread(target=worker,daemon=True).start()
    def _install_npcap_official_btn(self):
        self._append_opts("[npcap] Téléchargement+installation...\n")
        def worker(): ok,msg=install_npcap_official(oem_silent=(os.environ.get("NPCAP_OEM","0")=="1"),extra_args=os.environ.get("NPCAP_OEM_ARGS","")); self._append_opts(f"→ {msg}\n"); self._refresh_pcap_action()
        threading.Thread(target=worker,daemon=True).start()

    # ===================== Utils UI / Aide =====================
    def _set_text(self,widget: 'scrolledtext.ScrolledText', text:str): widget.configure(state=tk.NORMAL); widget.delete("1.0",tk.END); widget.insert(tk.END,text); widget.configure(state=tk.DISABLED)
    def _append(self,widget: 'scrolledtext.ScrolledText', text:str): widget.configure(state=tk.NORMAL); widget.insert(tk.END,text); widget.see(tk.END); widget.configure(state=tk.DISABLED)
    def _log(self,msg:str): ts=_dt.datetime.now().strftime("%H:%M:%S"); self._append(self.log,f"[{ts}] {msg}\n")
    def _refresh_pcap_action(self):
        ok, pc = refresh_pcap_status(); tk.messagebox.showinfo("Statut pcap",f"SCAPY_OK={ok}  PCAP={pc}"); self.status.set(f"pcap: SCAPY={ok} PCAP={pc}")
    def export_current_tab(self):
        idx=self.nb.index(self.nb.select()); name=self.nb.tab(idx,"text")
        path=filedialog.asksaveasfilename(defaultextension=".txt",filetypes=[("Texte","*.txt")],initialfile=f"netmon_{name}.txt")
        if not path: return
        mapping={"Interfaces":self.interfaces_text,"Connexions":self.conn_text,"Ports":self.ports_text,"Ping/Traceroute":self.ping_text,"Sniffer":self.sniff_text,"Sécurité (Ports)":self.sec_text,"Vulnérabilités":self.vuln_text,"Maintenance Windows (Basique)":self.maint_text,"Maintenance Windows (Avancée)":self.maint_adv,"Inventaire & Journaux":self.inv_text,"Rapports":self.rep_text,"Profils & Alertes":self.prof_text,"Options (Outils)":self.opt_output}
        content=mapping.get(name); data=content.get("1.0",tk.END) if content is not None else "Aucun contenu textuel à exporter."
        try:
            with open(path,"w",encoding="utf-8") as f: f.write(f"Export NetMon Pro - {name}\nLe: {_dt.datetime.now()}\n\n{data}")
            self.status.set(f"Exporté vers {path}")
        except Exception as e: tk.messagebox.showerror("Export",f"Échec: {e}")
    def show_about(self):
        msg=(f"{APP_NAME} v{VERSION}\nCréé par Chaouki Boussayri\n© 2025\n"
             f"Admin={is_admin()}  winget={bool(winget_path())}  choco={has_command('choco')}\n"
             f"Log: {LOG_PATH}\n\n"
             "Fonctions clés : SFC/DISM/Reset WU/Net/CHKDSK/Defender/SafeMode, Supervision PING/PORT/HTTP/SNMP, Cartographie, Sniffer, Rapports PDF.\n")
        try: tk.messagebox.showinfo("À propos",msg)
        except Exception: print(msg)

# ======================== FENÊTRE ERREUR GRAVE ==========================
def show_fatal_window(title: str, message: str):
    """Fenêtre de secours en cas de crash très précoce (avant chargement du thème)."""
    try:
        import tkinter as _tk
        from tkinter import scrolledtext as _st, ttk as _ttk
        root=_tk.Tk(); root.title(title); root.geometry("820x480")
        frm=_ttk.Frame(root); frm.pack(fill=_tk.BOTH,expand=True,padx=12,pady=12)
        _ttk.Label(frm,text=title,font=("Segoe UI",16,"bold")).pack(pady=(0,8))
        box=_st.ScrolledText(frm,height=16,wrap="word"); box.pack(fill=_tk.BOTH,expand=True)
        box.insert("end", message+f"\n\nJournal : {LOG_PATH}"); box.configure(state="disabled")
        btns=_ttk.Frame(frm); btns.pack(fill=_tk.X,pady=8)
        def open_log():
            if is_windows() and os.path.exists(LOG_PATH): subprocess.Popen(["explorer","/select,",LOG_PATH])
        _ttk.Button(btns,text="Ouvrir le journal",command=open_log).pack(side="left",padx=4)
        _ttk.Button(btns,text="Fermer",command=root.destroy).pack(side="right",padx=4)
        root.mainloop()
    except Exception:
        try:
            # Dernier recours : message box natif
            if is_windows():
                import ctypes
                ctypes.windll.user32.MessageBoxW(None, message+f"\n\nJournal : {LOG_PATH}", title, 0x10)
            else:
                print(message)
        except Exception:
            pass

# ======================== MAIN =========================================
def main():
    try:
        bootstrap_startup()
        load_runtime_libs()
        root=tk.Tk(); root.withdraw(); Theme.apply(root)
        consent=load_consent() or show_gdpr_signature(root)
        app=NetMonProApp(root,consent)
        # Recharger capteurs sauvegardés
        for s in app.profile.get("sensors",[]):
            app.sensor_kind.set(s.get("kind","PING")); app.sensor_name.set(s.get("name","sensor"))
            app.sensor_target.set(s.get("target","")); app.sensor_extra.set(s.get("extra","")); app.sensor_interval.set(int(s.get("interval",60)))
            app._sensor_add()
        root.deiconify(); root.mainloop()
    except Exception as e:
        logger.exception("Crash UI")
        msg=f"Erreur critique : {e}\n\nVeuillez transmettre le fichier de log pour diagnostic."
        show_fatal_window("NetMon Pro - Erreur critique", msg)

if __name__ == "__main__":
    main()
