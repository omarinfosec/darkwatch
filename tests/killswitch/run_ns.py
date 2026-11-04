"""Kill-switch test: run inside a fresh network namespace (unshare -rn).

on|off: builds a fake WireGuard container: eth0 on a Docker-like subnet with
a default route, wg0 with wg-quick's policy routing for AllowedIPs 0.0.0.0/0.
"on" also checks the hostname-Endpoint pinning and that a rerun is idempotent.
The resolver stand-ins behave like Alpine/musl (the tunnel image): getent has
no ahostsv4 and `getent hosts` gives only the IPv6 address of a dual-stack
name. "on-glibc" checks only the pinning, with glibc's getent ahostsv4.

peer-on|peer-off: this namespace (the tunnel container) gets two neighbours,
a darknet peer on eth0 and the VPN server on wg0, and a stand-in for Tor's
SocksPort on 0.0.0.0:9050. Probes who can open a connection to it.

Prints what each probe does; check.sh asserts the expected outcomes. Exits
non-zero, with its output, if the kill switch script fails.
Usage: unshare -rn python3 run_ns.py on|off|on-glibc|peer-on|peer-off
"""
import atexit, ctypes, errno, os, shutil, signal, socket, subprocess, sys, tempfile
from pyroute2 import IPRoute
MODE = sys.argv[1]
KS = "off" if MODE.endswith("off") else "on"
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
SCRIPT = os.path.join(REPO, "tunnels", "killswitch", "10-killswitch.sh")
TMP = tempfile.mkdtemp(prefix="dw-ks-"); atexit.register(shutil.rmtree, TMP, True)
CHILDREN = []
def _reap():
    for pid in CHILDREN:
        try: os.kill(pid, signal.SIGKILL); os.waitpid(pid, 0)
        except OSError: pass
atexit.register(_reap)

# ── environment for the kill switch script ──────────────────────────────────
env = dict(os.environ)
bindir = os.path.join(TMP, "bin"); os.makedirs(bindir)
if not any(os.access(os.path.join(d, "ip"), os.X_OK) for d in env["PATH"].split(os.pathsep)):
    # no iproute2: use the pyroute2-based shim
    with open(os.path.join(bindir, "ip"), "w") as f:
        f.write("#!" + sys.executable + "\n" + open(os.path.join(HERE, "ip_shim.py")).read())
    os.chmod(os.path.join(bindir, "ip"), 0o755)
# Resolver stand-ins, every call logged. vpn: A only; dual: A and AAAA;
# extra: only in /etc/hosts (extra_hosts), which busybox nslookup never reads.
STUBS = {"glibc": {
    "getent": r"""[ "$1" = ahostsv4 ] || exit 2
case "$2" in
  vpn.example.test) echo "203.0.113.7     STREAM vpn.example.test" ;;
  dual.example.test) echo "203.0.113.8     STREAM dual.example.test" ;;
  extra.example.test) echo "203.0.113.9     STREAM extra.example.test" ;;
  *) exit 2 ;;
esac""",
    "nslookup": "exit 127"},
  "musl": {
    "getent": r"""[ "$1" = hosts ] || { echo "Unknown database: $1" >&2; exit 1; }
case "$2" in
  dual.example.test) echo "2001:db8::8       dual.example.test" ;;
  extra.example.test) echo "203.0.113.9       extra.example.test" ;;
  *) exit 2 ;;
esac""",
    "nslookup": r"""[ "$1" = -type=a ] || exit 1
printf 'Server:\t\t127.0.0.11\nAddress:\t127.0.0.11:53\n\n'
case "$2" in
  vpn.example.test) a=203.0.113.7 ;;
  dual.example.test) a=203.0.113.8 ;;
  *) printf "** server can't find %s: NXDOMAIN\n\n" "$2"; exit 1 ;;
esac
printf 'Non-authoritative answer:\nName:\t%s\nAddress: %s\n\n' "$2" "$a"
"""}}
for tool, body in STUBS["glibc" if MODE == "on-glibc" else "musl"].items():
    with open(os.path.join(bindir, tool), "w") as f:
        f.write(f'#!/bin/sh\necho "{tool} $1 $2" >> "$GETENT_LOG"\n{body}\n')
    os.chmod(os.path.join(bindir, tool), 0o755)
confs = os.path.join(TMP, "wg_confs"); os.makedirs(confs)
hosts = os.path.join(TMP, "hosts")
with open(hosts, "w") as f: f.write("127.0.0.1\tlocalhost\n")
open(os.path.join(TMP, "getent.log"), "w").close()
env.update(PATH=bindir + os.pathsep + env["PATH"], DW_KS_WG_CONFS=confs, DW_KS_HOSTS_FILE=hosts,
           GETENT_LOG=os.path.join(TMP, "getent.log"))

def killswitch():
    r = subprocess.run(["bash", SCRIPT], env=env, capture_output=True, text=True)
    sys.stderr.write(r.stderr)
    if r.returncode:
        print(f"{r.stdout}FAIL: 10-killswitch.sh exited {r.returncode}", file=sys.stderr)
        sys.exit(1)
    return r.stdout.strip()

def ipt_hooks(ipt):
    out = lambda chain: subprocess.run([ipt, "-S", chain], capture_output=True, text=True).stdout
    return f'OUTPUT->DW_KILLSWITCH x{out("OUTPUT").count("-j DW_KILLSWITCH")}, INPUT->DW_KS_IN x{out("INPUT").count("-j DW_KS_IN")}'

# ── namespaces (peer mode) ──────────────────────────────────────────────────
libc = ctypes.CDLL(None, use_errno=True)
CLONE_NEWNET = 0x40000000
def _ok(rc):
    if rc != 0: e = ctypes.get_errno(); raise OSError(e, os.strerror(e))
def fork_in(ns_pid, fn):
    """Fork; the child enters ns_pid's netns (None: stay here), sends fn(send)'s result, exits."""
    r, w = os.pipe(); pid = os.fork()
    if pid == 0:
        os.close(r)
        send = lambda s: os.write(w, (str(s) + "\n").encode())
        try:
            if ns_pid is not None:
                fd = os.open(f"/proc/{ns_pid}/ns/net", os.O_RDONLY); _ok(libc.setns(fd, CLONE_NEWNET))
            send(fn(send))
        except BaseException as e:
            send(f"error: {e!r}")
        os._exit(0)
    os.close(w); CHILDREN.append(pid)
    with os.fdopen(r) as f: return pid, f.readline().strip()
def new_netns():
    def hold(send):
        _ok(libc.unshare(CLONE_NEWNET)); send("ok")
        while True: signal.pause()
    pid, st = fork_in(None, hold)
    if st != "ok": sys.exit(f"FAIL: new netns: {st}")
    return pid
def run_in(ns_pid, fn): return fork_in(ns_pid, lambda send: fn())[1]
def listen(ns_pid, addr, port):
    def serve(send):
        s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((addr, port)); s.listen(8); send("ok")
        while True: s.accept()[0].close()
    st = fork_in(ns_pid, serve)[1]
    if st != "ok": sys.exit(f"FAIL: listen {addr}:{port}: {st}")
def connect(dst, port):
    s = socket.socket(); s.settimeout(1.5)
    try: s.connect((dst, port)); return "connected"
    except socket.timeout: return "blocked (timeout)"
    except OSError as e: return f"blocked ({errno.errorcode.get(e.errno, e.errno)})"
    finally: s.close()

def peer():
    dn, vpn = new_netns(), new_netns()
    with IPRoute() as ipr:
        ipr.link("set", index=ipr.link_lookup(ifname="lo")[0], state="up")
        ipr.link("add", ifname="eth0", kind="veth", peer="dneth")
        ipr.link("add", ifname="wg0", kind="veth", peer="vpnwg")
        ipr.link("set", index=ipr.link_lookup(ifname="dneth")[0], net_ns_pid=dn)
        ipr.link("set", index=ipr.link_lookup(ifname="vpnwg")[0], net_ns_pid=vpn)
        eth, wg = ipr.link_lookup(ifname="eth0")[0], ipr.link_lookup(ifname="wg0")[0]
        ipr.addr("add", index=eth, address="172.31.250.2", prefixlen=24); ipr.link("set", index=eth, state="up")
        ipr.addr("add", index=wg, address="10.2.0.2", prefixlen=32); ipr.link("set", index=wg, state="up")
        ipr.route("add", dst="0.0.0.0/0", gateway="172.31.250.1")       # Docker bridge default route
        ipr.route("add", dst="10.2.0.1/32", oif=wg)
    def setup(ifname, addr, peer=None):
        def fn():
            with IPRoute() as ipr:
                ipr.link("set", index=ipr.link_lookup(ifname="lo")[0], state="up")
                i = ipr.link_lookup(ifname=ifname)[0]; ipr.link("set", index=i, state="up")
                ipr.addr("add", index=i, address=addr, prefixlen=32 if peer else 24)
                if peer: ipr.route("add", dst=peer + "/32", oif=i)
            return "ok"
        return fn
    for ns, fn in ((dn, setup("dneth", "172.31.250.250")), (vpn, setup("vpnwg", "10.2.0.1", "10.2.0.2"))):
        st = run_in(ns, fn)
        if st != "ok": sys.exit(f"FAIL: peer netns setup: {st}")
    if KS == "on": print(killswitch())
    listen(None, "0.0.0.0", 9050); listen(vpn, "10.2.0.1", 443)        # tor SocksPort / a guard via the tunnel
    p = f"[{MODE}]"
    print(p, "darknet  -> tunnel 172.31.250.2:9050 :", run_in(dn, lambda: connect("172.31.250.2", 9050)))
    print(p, "VPN peer -> tunnel 10.2.0.2:9050     :", run_in(vpn, lambda: connect("10.2.0.2", 9050)))
    print(p, "tunnel   -> VPN 10.2.0.1:443 via wg0 :", connect("10.2.0.1", 443))
    print(p, "loopback -> 127.0.0.1:9050           :", connect("127.0.0.1", 9050))

if MODE.startswith("peer-"):
    peer(); sys.exit(0)

# ── on|off: egress probes ───────────────────────────────────────────────────
ipr = IPRoute()
lo = ipr.link_lookup(ifname="lo")[0]; ipr.link("set", index=lo, state="up")
ipr.link("add", ifname="eth0", kind="veth", peer="xeth"); eth = ipr.link_lookup(ifname="eth0")[0]
ipr.addr("add", index=eth, address="172.31.250.2", prefixlen=24); ipr.link("set", index=eth, state="up")
ipr.route("add", dst="0.0.0.0/0", gateway="172.31.250.1")          # Docker bridge default route
def wg_up():
    ipr.link("add", ifname="wg0", kind="veth", peer="xwg"); wg = ipr.link_lookup(ifname="wg0")[0]
    ipr.addr("add", index=wg, address="10.2.0.2", prefixlen=32); ipr.link("set", index=wg, state="up")
    # what wg-quick does for AllowedIPs = 0.0.0.0/0
    ipr.route("add", dst="0.0.0.0/0", oif=wg, table=51820)
    ipr.rule("add", fwmark=0xca6c, fwmask=0xffffffff, table=51820, action="FR_ACT_TO_TBL", flags=0x2)  # "not fwmark" (FIB_RULE_INVERT)
    ipr.rule("add", table=254, suppress_prefixlength=0, priority=32765)
def wg_down():
    ipr.link("del", ifname="wg0")
def probe(dst, mark=None):
    s = socket.socket(); s.settimeout(1.0)
    if mark: s.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
    try: s.connect((dst, 443)); return "connected?!"
    except ConnectionRefusedError: return "REJECTED"
    except OSError as e:
        return "REJECTED" if e.errno in (errno.EPERM, errno.ECONNREFUSED) else "allowed (left via route, no reply)"
    finally: s.close()
if KS == "on":
    # Endpoints: hostnames (A only, dual-stack, /etc/hosts only), one that
    # doesn't resolve, IP literals (never looked up).
    for name, ep in (("wg0", "vpn.example.test:51820"), ("wg1", "nx.example.test:51820"),
                     ("wg2", "198.51.100.1:51820"), ("wg3", "[2001:db8::1]:51820"),
                     ("wg4", "dual.example.test:51820"), ("wg5", "extra.example.test:51820")):
        with open(os.path.join(confs, name + ".conf"), "w") as f:
            f.write(f"[Interface]\nAddress = 10.2.0.2/32\n\n[Peer]\nEndpoint = {ep}\nAllowedIPs = 0.0.0.0/0\n")
    if MODE == "on-glibc":
        # No earlier pins and no trailing newline: the pins are appended.
        with open(hosts, "w") as f: f.write("127.0.0.1\tlocalhost")
    else:
        with open(hosts, "a") as f: f.write("198.51.100.9 vpn.example.test # dw-killswitch endpoint\n")  # stale pin
    print(killswitch())
    if MODE == "on-glibc":
        for line in open(hosts).read().splitlines(): print(f"[{MODE}] hosts: {line}")
        sys.exit(0)
    killswitch()   # a restart runs it again
    for line in open(hosts).read().splitlines(): print(f"[on] hosts: {line}")
    print("[on] looked up:", " ".join(sorted({l.split()[2] for l in open(env["GETENT_LOG"])})))
    print("[on] iptables hooks:", ipt_hooks("iptables"))
    if subprocess.run(["ip6tables", "-L", "OUTPUT", "-n"], capture_output=True).returncode == 0:
        print("[on] ip6tables hooks:", ipt_hooks("ip6tables"))
wg_up()
print(f"[{KS}] tunnel UP   internet 1.1.1.1      :", probe("1.1.1.1"))
print(f"[{KS}] tunnel UP   darknet 172.31.250.250 :", probe("172.31.250.250"))
print(f"[{KS}] tunnel UP   WG endpoint (marked)  :", probe("185.1.1.1", mark=0xca6c))
wg_down()
print(f"[{KS}] tunnel DOWN internet 1.1.1.1      :", probe("1.1.1.1"))
print(f"[{KS}] tunnel DOWN darknet 172.31.250.250 :", probe("172.31.250.250"))
