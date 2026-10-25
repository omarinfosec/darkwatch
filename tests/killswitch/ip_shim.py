#!/usr/bin/env python3
# Minimal `ip -4|-6 -o addr show [scope global]` shim for the kill-switch test.
import sys, socket
from pyroute2 import IPRoute
fam = socket.AF_INET6 if "-6" in sys.argv else socket.AF_INET
with IPRoute() as ipr:
    names = {l["index"]: l.get_attr("IFLA_IFNAME") for l in ipr.get_links()}
    for a in ipr.get_addr(family=fam):
        if fam == socket.AF_INET6 and a["scope"] != 0: continue
        n = names[a["index"]]
        print(f'{a["index"]}: {n}    {"inet6" if fam==socket.AF_INET6 else "inet"} {a.get_attr("IFA_ADDRESS")}/{a["prefixlen"]} scope global {n}')
