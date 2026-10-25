"""Kill-switch test: run inside a fresh network namespace (unshare -rn).

Builds a fake WireGuard container: eth0 on a Docker-like subnet with a
default route, wg0 with wg-quick's policy routing for AllowedIPs 0.0.0.0/0.
Prints what each probe does; check.sh asserts the expected outcomes.
Usage: unshare -rn python3 run_ns.py on|off
"""
import errno, socket, subprocess, sys, os
from pyroute2 import IPRoute
KS = sys.argv[1]
HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
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
env = dict(os.environ)
if not any(os.access(os.path.join(d, "ip"), os.X_OK) for d in env["PATH"].split(os.pathsep)):
    # no iproute2: use the pyroute2-based shim
    shim_dir = os.path.join(HERE, ".bin"); os.makedirs(shim_dir, exist_ok=True)
    tgt = os.path.join(shim_dir, "ip")
    if not os.path.exists(tgt):
        with open(tgt, "w") as f: f.write("#!" + sys.executable + "\n" + open(os.path.join(HERE, "ip_shim.py")).read())
        os.chmod(tgt, 0o755)
    env["PATH"] = shim_dir + os.pathsep + env["PATH"]
if KS == "on":
    print(subprocess.run(["bash", os.path.join(REPO, "tunnels", "killswitch", "10-killswitch.sh")], env=env, capture_output=True, text=True).stdout.strip())
wg_up()
print(f"[{KS}] tunnel UP   internet 1.1.1.1      :", probe("1.1.1.1"))
print(f"[{KS}] tunnel UP   darknet 172.31.250.250 :", probe("172.31.250.250"))
print(f"[{KS}] tunnel UP   WG endpoint (marked)  :", probe("185.1.1.1", mark=0xca6c))
wg_down()
print(f"[{KS}] tunnel DOWN internet 1.1.1.1      :", probe("1.1.1.1"))
print(f"[{KS}] tunnel DOWN darknet 172.31.250.250 :", probe("172.31.250.250"))
