Build Your Own Virtual Private Cloud (VPC) on Linux

Linux Networking, Isolation, and Routing from First Principles


🧭 Overview

In this project, I recreated a Virtual Private Cloud (VPC) from scratch using only native Linux networking tools (ip, iptables, bridge, ip netns).

This setup simulates how cloud providers (like AWS or GCP) implement networking under the hood — including:

Subnets

Routing

NAT (Internet Gateway)

VPC isolation

Firewall/Security Groups

Optional VPC Peering


All of this is automated with a Python CLI tool called vpcctl.


---

🎯 Objectives

By the end of this project, the environment supports:

✅ Create and delete VPCs (Linux bridges)

✅ Add subnets (as network namespaces)

✅ Enable routing between subnets within a VPC

✅ Configure NAT gateway for internet access

✅ Demonstrate private/public subnet isolation

✅ Apply firewall policies from JSON (Security Groups)

✅ Optionally peer two VPCs

✅ Automate full lifecycle: create → test → teardown



---

🧰 Tech Stack

Component	Purpose

Python 3	Custom CLI (vpcctl.py)
iproute2	ip, ip netns, ip link, ip route
iptables	NAT & firewall rules
bridge-utils	Virtual bridge management
bash & Makefile	Automation & cleanup
Ubuntu 22.04+ VM	Safe isolated environment



---

⚙️ Prerequisites

Ubuntu Linux VM (preferred)

Root access (use sudo)

Internet connection for package installation



---

📦 Installation

# Clone repository
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>

# Install dependencies
sudo make install-deps

# Make scripts executable
sudo chmod +x vpcctl.py cleanup.sh validate-vpc.sh


---

🏗️ Project Architecture

Diagram:

+---------------------------+
                     |       VPC (br-vpc1)       |
                     |  10.0.0.1/16 (Gateway)    |
                     +-------------+-------------+
                                   |
          -------------------------------------------------
          |                                               |
  +---------------+                               +---------------+
  | Public Subnet |                               | Private Subnet|
  | vpc1-public   |                               | vpc1-private  |
  | 10.0.1.0/24   |                               | 10.0.2.0/24   |
  | NAT Enabled   |                               | Internal Only |
  +-------+-------+                               +-------+-------+
          |                                               |
       (veth pair)                                     (veth pair)
          |                                               |
   Internet (via eth0)                              No Internet Access



🚀 Usage Examples

🧩 1. Create a VPC

sudo ./vpcctl.py create-vpc --name vpc1 --gateway 10.0.0.1/16

🌐 2. Add Subnets

sudo ./vpcctl.py add-subnet --vpc vpc1 --name public --cidr 10.0.1.0/24 --ip 10.0.1.10
sudo ./vpcctl.py add-subnet --vpc vpc1 --name private --cidr 10.0.2.0/24 --ip 10.0.2.10

🧭 3. Inspect the VPC

sudo ./vpcctl.py inspect --vpc vpc1

📸 Screenshot:
Show bridge (br-vpc1), namespaces (vpc1-public, vpc1-private), and IPs.




🌍 4. Enable NAT (Public → Internet Access)

sudo ./vpcctl.py enable-nat --vpc vpc1 --subnet public --subnet-cidr 10.0.1.0/24 --out-if eth0




🌐 5. Deploy a Web Server Inside Public Subnet

sudo ./vpcctl.py start-http --vpc vpc1 --subnet public --port 80

📸 Screenshot:
Run curl http://10.0.1.10 → Expect HTML output <h1>vpcctl vpc1-public</h1>.


🧪 6. Validate Connectivity

sudo ip netns exec vpc1-public ping -c 2 10.0.2.10    # ✅ public → private
sudo ip netns exec vpc1-public ping -c 2 8.8.8.8       # ✅ public → internet
sudo ip netns exec vpc1-private ping -c 2 8.8.8.8      # ❌ private → internet (blocked)

📸 Screenshot:
Show both success and failure pings.




🔥 7. Apply Firewall Policy

policy-public.json:

{
  "subnet": "10.0.1.0/24",
  "ingress": [
    {"port": 80, "protocol": "tcp", "action": "allow"},
    {"port": 22, "protocol": "tcp", "action": "deny"},
    {"port": 0, "protocol": "icmp", "action": "allow"}
  ]
}

Apply it:

sudo ./vpcctl.py apply-policy --vpc vpc1 --subnet public --policy-file policy-public.json

Test:

nc -vz 10.0.1.10 22 || true   # ❌ blocked
curl -I http://10.0.1.10       # ✅ allowed



🧮 8. Automated Validation Script

sudo ./validate-vpc.sh vpc1 10.0.1.10 10.0.2.10

Expected Output:

[PASS] public -> private
[PASS] public -> internet
[PASS] private -> internet blocked
[PASS] curl to public webserver



🧹 9. Cleanup & Teardown

sudo ./vpcctl.py stop-http --vpc vpc1 --subnet public
sudo ./vpcctl.py delete-vpc --name vpc1
sudo ./cleanup.sh

Verify:

ip netns list
ip link show | grep br-

✅ Expected: No namespaces or bridges remain.



🧠 How It Works (Concept Summary)

Component	Role	Linux Primitive

VPC	Central virtual router	bridge
Subnets	Isolated environments	network namespace
Connection	Links between subnets and bridge	veth pair
Routing	Internal communication	ip route
NAT	Internet access simulation	iptables -t nat
Security Groups	Firewall per subnet	iptables rules
Peering	Controlled inter-VPC connection	veth between bridges
CLI Tool	Automation wrapper	Python subprocess + ip commands



---

