#!/usr/bin/env python3
"""
vpcctl.py — simple VPC lab controller using Linux network primitives.

Usage examples (run as root / sudo):
  sudo ./vpcctl.py create-vpc --name vpc1 --cidr 10.0.0.0/16
  sudo ./vpcctl.py add-subnet --vpc vpc1 --name public --cidr 10.0.1.0/24 --ip 10.0.1.10
  sudo ./vpcctl.py add-subnet --vpc vpc1 --name private --cidr 10.0.2.0/24 --ip 10.0.2.10
  sudo ./vpcctl.py enable-nat --vpc vpc1 --subnet public --out-if eth0
  sudo ./vpcctl.py apply-policy --vpc vpc1 --subnet public --policy-file ./policy.json
  sudo ./vpcctl.py start-http --vpc vpc1 --subnet public --port 80
  sudo ./vpcctl.py inspect --vpc vpc1
  sudo ./vpcctl.py delete-vpc --name vpc1
"""

import argparse, subprocess, shlex, json, os, sys, logging, time

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger("vpcctl")

def run(cmd, check=True):
    log.info("+ %s", cmd)
    parts = shlex.split(cmd)
    res = subprocess.run(parts, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and res.returncode != 0:
        log.error("Command failed: %s\nstdout: %s\nstderr: %s", cmd, res.stdout, res.stderr)
        raise subprocess.CalledProcessError(res.returncode, cmd, res.stdout, res.stderr)
    return res

def exists_bridge(name):
    res = subprocess.run(["ip", "link", "show", name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return res.returncode == 0

def exists_namespace(ns):
    res = subprocess.run(["ip", "netns", "list"], stdout=subprocess.PIPE, text=True)
    return ns in res.stdout.split()

def ensure_ip_forwarding():
    run("sysctl -w net.ipv4.ip_forward=1")
    # persist
    with open("/etc/sysctl.conf", "a") as f:
        f.write("\n# enabled by vpcctl\nnet.ipv4.ip_forward=1\n")

def create_vpc(args):
    br = f"br-{args.name}"
    if exists_bridge(br):
        log.info("Bridge %s already exists — skipping create", br)
    else:
        run(f"ip link add name {br} type bridge")
        run(f"ip link set dev {br} up")
    # Add main gateway address for VPC (the user can provide optional gw)
    if args.gateway:
        # Check if address already present
        res = run(f"ip addr show dev {br}", check=False)
        if args.gateway not in res.stdout:
            run(f"ip addr add {args.gateway} dev {br}")
    log.info("VPC %s created (bridge %s)", args.name, br)

def delete_vpc(args):
    br = f"br-{args.name}"
    # find namespaces that belong to vpc (naming convention: vpcname-subnet)
    res = run("ip netns list", check=False)
    for line in res.stdout.splitlines():
        ns = line.strip().split()[0]
        if ns.startswith(f"{args.name}-"):
            try:
                run(f"ip netns delete {ns}")
                log.info("Deleted namespace %s", ns)
            except Exception as e:
                log.warning("Failed delete namespace %s: %s", ns, e)
    # delete peering links that mention bridge (best-effort)
    # bring down & delete bridge
    if exists_bridge(br):
        try:
            run(f"ip link set {br} down")
            run(f"ip link del {br}")
            log.info("Deleted bridge %s", br)
        except Exception as e:
            log.error("Failed to delete bridge %s: %s", br, e)
    else:
        log.info("Bridge %s not present", br)
    # flush iptables rules with 'vpcctl' comment — best-effort cleanup
    # (we tag NAT rules with comment 'vpcctl:{vpc}:{subnet}')
    # remove rules that include 'vpcctl:'
    res = run("iptables -t nat -S", check=False)
    for line in res.stdout.splitlines():
        if "vpcctl:" in line:
            # translate -S line to delete using -D
            candidate = "-t nat " + line.replace("-A", "-D", 1)
            try:
                run(f"iptables {candidate}", check=False)
            except Exception:
                pass
    # filter forward table
    res = run("iptables -S", check=False)
    for line in res.stdout.splitlines():
        if "vpcctl:" in line:
            candidate = line.replace("-A", "-D", 1)
            try:
                run(f"iptables {candidate}", check=False)
            except Exception:
                pass
    log.info("Cleanup attempted for VPC %s (some rules may remain if mutated manually)", args.name)

def add_subnet(args):
    vpc = args.vpc
    name = args.name
    cidr = args.cidr
    ip = args.ip
    br = f"br-{vpc}"
    ns = f"{vpc}-{name}"
    if not exists_bridge(br):
        raise SystemExit(f"Bridge {br} does not exist. create-vpc first.")
    if exists_namespace(ns):
        log.info("Namespace %s already exists — skipping", ns)
        return
    # create namespace
    run(f"ip netns add {ns}")
    # create veth pair
    host_end = f"{ns}-br"
    ns_end = f"{ns}-if"
    run(f"ip link add {ns_end} type veth peer name {host_end}")
    # move ns_end to namespace
    run(f"ip link set {ns_end} netns {ns}")
    # connect host_end to bridge
    run(f"ip link set {host_end} master {br}")
    run(f"ip link set {host_end} up")
    # bring up interface inside namespace and assign IP
    run(f"ip netns exec {ns} ip link set dev {ns_end} up")
    run(f"ip netns exec {ns} ip addr add {ip}/{cidr.split('/')[-1]} dev {ns_end}")
    # configure bridge gateway for the subnet — set .1 as gateway (if not present)
    # compute subnet network prefix and set .1
    base = cidr.split('/')[0]
    octets = base.split('.')
    gw = f"{octets[0]}.{octets[1]}.{octets[2]}.1/{cidr.split('/')[-1]}"
    # add gw to bridge if not already present
    res = run(f"ip addr show dev {br}", check=False)
    if octets[0] + "." + octets[1] + "." + octets[2] + ".1" not in res.stdout:
        run(f"ip addr add {gw} dev {br}", check=False)
    # set default route inside namespace via .1
    gw_ip = ".".join(octets[0:3] + ["1"])
    run(f"ip netns exec {ns} ip route add default via {gw_ip}")
    log.info("Added subnet %s (ns=%s ip=%s cidr=%s) to VPC %s", name, ns, ip, cidr, vpc)

def remove_subnet(args):
    ns = f"{args.vpc}-{args.name}"
    if exists_namespace(ns):
        run(f"ip netns delete {ns}")
        log.info("Deleted namespace %s", ns)
    else:
        log.info("Namespace %s not present", ns)

def enable_nat(args):
    vpc = args.vpc
    subnet = args.subnet
    out_if = args.out_if
    subnet_cidr = args.subnet_cidr
    tag = f"vpcctl:{vpc}:{subnet}"
    # Add NAT in POSTROUTING with comment
    # iptables -t nat -A POSTROUTING -s <subnet> -o <out_if> -j MASQUERADE -m comment --comment "vpcctl:..."
    # But iptables requires comment module at match position: -m comment --comment "..."
    cmd = f"iptables -t nat -C POSTROUTING -s {subnet_cidr} -o {out_if} -j MASQUERADE -m comment --comment {shlex.quote(tag)}"
    res = run(cmd, check=False)
    if res.returncode == 0:
        log.info("NAT rule already present for %s", subnet_cidr)
    else:
        run(f"iptables -t nat -A POSTROUTING -s {subnet_cidr} -o {out_if} -j MASQUERADE -m comment --comment {shlex.quote(tag)}")
        run(f"iptables -A FORWARD -i {out_if} -o br-{vpc} -m state --state RELATED,ESTABLISHED -j ACCEPT -m comment --comment {shlex.quote(tag)}")
        run(f"iptables -A FORWARD -i br-{vpc} -o {out_if} -j ACCEPT -m comment --comment {shlex.quote(tag)}")
        log.info("NAT and FORWARD rules added for %s via %s", subnet_cidr, out_if)

def apply_policy(args):
    vpc = args.vpc
    subnet = args.subnet
    ns = f"{vpc}-{subnet}"
    if not exists_namespace(ns):
        raise SystemExit(f"Namespace {ns} not found. Create subnet first.")
    policy_file = args.policy_file
    with open(policy_file) as f:
        policy = json.load(f)
    # basic approach: flush INPUT chain and apply rules, then set default policy
    run(f"ip netns exec {ns} iptables -F")
    run(f"ip netns exec {ns} iptables -P INPUT DROP")
    run(f"ip netns exec {ns} iptables -P FORWARD DROP")
    # apply ingress rules
    for rule in policy.get("ingress", []):
        proto = rule.get("protocol", "tcp")
        port = rule.get("port")
        action = rule.get("action", "allow")
        if proto.lower() == "icmp":
            match = "-p icmp"
            portpart = ""
        else:
            match = f"-p {proto}"
            portpart = f"--dport {port}" if port else ""
        if action == "allow":
            run(f"ip netns exec {ns} iptables -I INPUT {match} {portpart} -j ACCEPT")
        else:
            run(f"ip netns exec {ns} iptables -I INPUT {match} {portpart} -j DROP")
    # allow established related
    run(f"ip netns exec {ns} iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT")
    log.info("Policy applied to %s from %s", ns, policy_file)

def start_http(args):
    ns = f"{args.vpc}-{args.subnet}"
    if not exists_namespace(ns):
        raise SystemExit(f"{ns} not found")
    port = args.port
    # run simple http server in background within namespace using nohup
    # put a small index file
    run(f"ip netns exec {ns} mkdir -p /tmp/vpcctl-www-{ns}", check=False)
    run(f"ip netns exec {ns} bash -c 'echo \"<h1>vpcctl {ns}</h1>\" > /tmp/vpcctl-www-{ns}/index.html'", check=False)
    # start server using python -m http.server in background and save PID
    cmd = f"ip netns exec {ns} nohup python3 -m http.server {port} --directory /tmp/vpcctl-www-{ns} >/tmp/vpcctl-{ns}.log 2>&1 & echo $! > /tmp/vpcctl-{ns}.pid"
    run(cmd, check=False)
    log.info("HTTP server started inside %s on port %d", ns, port)

def stop_http(args):
    ns = f"{args.vpc}-{args.subnet}"
    # best effort: kill python process inside namespace by reading pid file
    pidfile = f"/tmp/vpcctl-{ns}.pid"
    if os.path.exists(pidfile):
        with open(pidfile) as f:
            pid = f.read().strip()
        try:
            run(f"kill {pid}", check=False)
            os.remove(pidfile)
            log.info("Stopped HTTP server (pid %s) for %s", pid, ns)
        except Exception as e:
            log.warning("Could not stop pid %s: %s", pid, e)
    else:
        # fallback: kill python server processes inside namespace
        run(f"ip netns exec {ns} pkill -f 'python3 -m http.server'", check=False)
        log.info("Attempted to stop any http.server inside %s", ns)

def inspect(args):
    vpc = args.vpc
    br = f"br-{vpc}"
    print("=== VPC:", vpc)
    run(f"ip link show {br}", check=False)
    run(f"ip addr show dev {br}", check=False)
    print("\nNamespaces:")
    res = run("ip netns list", check=False)
    for line in res.stdout.splitlines():
        ns = line.split()[0]
        if ns.startswith(f"{vpc}-"):
            print(" -", ns)
            run(f"ip netns exec {ns} ip addr", check=False)
            run(f"ip netns exec {ns} ip route", check=False)
            run(f"ip netns exec {ns} iptables -S", check=False)

def peer_vpcs(args):
    v1 = args.vpc1; v2 = args.vpc2
    br1 = f"br-{v1}"; br2 = f"br-{v2}"
    if not exists_bridge(br1) or not exists_bridge(br2):
        raise SystemExit("Both VPC bridges must exist to create peering.")
    # create a veth pair and attach one end to each bridge
    peer1 = f"peer-{v1}-{v2}"
    peer2 = f"peer-{v2}-{v1}"
    # if link already exists, skip
    res = run(f"ip link show {peer1}", check=False)
    if res.returncode == 0:
        log.info("Peer link %s already present", peer1)
        return
    run(f"ip link add {peer1} type veth peer name {peer2}")
    run(f"ip link set {peer1} master {br1}")
    run(f"ip link set {peer2} master {br2}")
    run(f"ip link set {peer1} up")
    run(f"ip link set {peer2} up")
    # Add routes on host to route between VPC ranges if provided
    if args.vpc1_cidr and args.vpc2_cidr:
        # Add route to vpc2 network via peer1 for vpc1 and vice-versa
        run(f"ip route add {args.vpc2_cidr} dev {peer1}", check=False)
        run(f"ip route add {args.vpc1_cidr} dev {peer2}", check=False)
    log.info("Peering created between %s and %s", v1, v2)

def parse_args():
    p = argparse.ArgumentParser(prog="vpcctl")
    sub = p.add_subparsers(dest="cmd")
    # create-vpc
    c = sub.add_parser("create-vpc")
    c.add_argument("--name", required=True)
    c.add_argument("--cidr", required=False, help="Not used directly, informational")
    c.add_argument("--gateway", required=False, help="gateway ip on bridge e.g. 10.0.0.1/16")
    # delete-vpc
    d = sub.add_parser("delete-vpc")
    d.add_argument("--name", required=True)
    # add-subnet
    a = sub.add_parser("add-subnet")
    a.add_argument("--vpc", required=True)
    a.add_argument("--name", required=True)
    a.add_argument("--cidr", required=True, help="e.g. 10.0.1.0/24")
    a.add_argument("--ip", required=True, help="ip for namespace host e.g. 10.0.1.10")
    # remove-subnet
    r = sub.add_parser("remove-subnet")
    r.add_argument("--vpc", required=True)
    r.add_argument("--name", required=True)
    # enable-nat
    n = sub.add_parser("enable-nat")
    n.add_argument("--vpc", required=True)
    n.add_argument("--subnet", required=True)
    n.add_argument("--subnet-cidr", required=True)
    n.add_argument("--out-if", required=True)
    # apply-policy
    ppol = sub.add_parser("apply-policy")
    ppol.add_argument("--vpc", required=True)
    ppol.add_argument("--subnet", required=True)
    ppol.add_argument("--policy-file", required=True)
    # start-http / stop-http
    s = sub.add_parser("start-http")
    s.add_argument("--vpc", required=True)
    s.add_argument("--subnet", required=True)
    s.add_argument("--port", type=int, default=80)
    st = sub.add_parser("stop-http")
    st.add_argument("--vpc", required=True)
    st.add_argument("--subnet", required=True)
    # inspect
    i = sub.add_parser("inspect")
    i.add_argument("--vpc", required=True)
    # peer
    pr = sub.add_parser("peer")
    pr.add_argument("--vpc1", required=True)
    pr.add_argument("--vpc2", required=True)
    pr.add_argument("--vpc1-cidr", required=False)
    pr.add_argument("--vpc2-cidr", required=False)
    return p.parse_args()

def main():
    if os.geteuid() != 0:
        raise SystemExit("vpcctl must be run as root (sudo).")
    args = parse_args()
    if args.cmd == "create-vpc":
        ensure_ip_forwarding()
        create_vpc(args)
    elif args.cmd == "delete-vpc":
        delete_vpc(args)
    elif args.cmd == "add-subnet":
        add_subnet(args)
    elif args.cmd == "remove-subnet":
        remove_subnet(args)
    elif args.cmd == "enable-nat":
        enable_nat(args)
    elif args.cmd == "apply-policy":
        apply_policy(args)
    elif args.cmd == "start-http":
        start_http(args)
    elif args.cmd == "stop-http":
        stop_http(args)
    elif args.cmd == "inspect":
        inspect(args)
    elif args.cmd == "peer":
        peer_vpcs(args)
    else:
        print("No command — use --help")

if __name__ == "__main__":
    main()
