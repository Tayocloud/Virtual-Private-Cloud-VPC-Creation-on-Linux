SHELL := /bin/bash
VPC_NAME := vpc1
OUT_IF := eth0        # <-- change this to your VM's outbound interface if different
PUBLIC_CIDR := 10.0.1.0/24
PRIVATE_CIDR := 10.0.2.0/24
PUBLIC_IP := 10.0.1.10
PRIVATE_IP := 10.0.2.10
POLICY := policy-public.json

.PHONY: all install-deps create-vpc add-subnets enable-nat apply-policy start-http test stop-http delete-vpc clean cleanup

all: install-deps

install-deps:
	sudo apt update
	sudo apt install -y iproute2 iptables bridge-utils python3

create-vpc:
	sudo ./vpcctl.py create-vpc --name $(VPC_NAME) --gateway 10.0.0.1/16

add-subnets:
	sudo ./vpcctl.py add-subnet --vpc $(VPC_NAME) --name public --cidr $(PUBLIC_CIDR) --ip $(PUBLIC_IP)
	sudo ./vpcctl.py add-subnet --vpc $(VPC_NAME) --name private --cidr $(PRIVATE_CIDR) --ip $(PRIVATE_IP)

enable-nat:
	sudo ./vpcctl.py enable-nat --vpc $(VPC_NAME) --subnet public --subnet-cidr $(PUBLIC_CIDR) --out-if $(OUT_IF)

apply-policy:
	sudo ./vpcctl.py apply-policy --vpc $(VPC_NAME) --subnet public --policy-file $(POLICY)

start-http:
	sudo ./vpcctl.py start-http --vpc $(VPC_NAME) --subnet public --port 80

test:
	@echo "Running validation tests..."
	sudo bash ./validate-vpc.sh $(VPC_NAME) $(PUBLIC_IP) $(PRIVATE_IP)

stop-http:
	sudo ./vpcctl.py stop-http --vpc $(VPC_NAME) --subnet public

delete-vpc:
	sudo ./vpcctl.py delete-vpc --name $(VPC_NAME)

clean: stop-http delete-vpc cleanup

# Completely remove any leftovers (best-effort)
cleanup:
	sudo bash ./cleanup.sh
