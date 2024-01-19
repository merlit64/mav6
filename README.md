# Managment Plane Application IPv6 (MAV6) #

MAV6 is an IPv6 testing application for Cisco networking devices. The objective of MAV6 is to verify compatibility of managment plane protocols in an IPv6 environment. MAV6 requires an Ubuntu test server to conduct testing on a IPv6 device. The test server and test device take turns acting as a server and client in each managment plane test. MAV6 produces a table of all test results as pass/fail. 
*Note: Test Device will be reconfigured during testing. Do not use a production device. Assume all configurations on the Test Device will be lost.

## Information Needed ##

- Test Device
  - hostname
  - IPv4 and IPv6 address
  - username
  - password (default and enable)
  - OS
- Ubuntu Server
  - IPv4 and IPv6 address
  - username and password
  - NTP server IPv4 and IPv6 addresses reachable by test device

## Test Device Configuration ##

- Test Device
  - no ntp server X.X.X.X/X:X:X:X::X
  - line vty 0 4
    - Transport input all
  - ipv6 unicast-routing
  - ip scp server enable

## Ubuntu Server Configuration ##

- Ubuntu Server
  - Setup Ubuntu Server from scratch
    - Install VSCode or similar IDE
  - Remote login: on
  - apt install update
  - apt install upgrade
  - apt install sshpass
  - apt install telnetd telnet

## MAV6 Download and Setup ##
- git clone https://github.com/merlit64/mav6.git
- change ’sample_secrets.py’ to ’secrets.py’ and configure appropriately with authentication info
- configure test_configuration to indicate which tests will execute
- Testbed
  - create mav6/pyATS directory
  - move ’sample_testbed.yaml’ to pyATS directory
  - change name of ‘sample_testbed.yaml’ to ‘testbed.yaml’



Paul instructions

START HERE 
Install an Ubuntu 22.04 (python 3.10.12) Virtual Machine
sudo apt update
sudo apt upgrade

- Give it and IPv4 and and IPv6 address
- Install your test device, give it an IPv4 and/or IPv6 address and a hostname (dont forget ipv6 unicast-routing global command)
- Make sure there is communication between the 2 devices
- Make sure ssh is enabled to the test device, use "login local" to user the local user database and make sure you add a username (required for mav6 use)
- Make sure telnet is enabled to the test device (if you will be testing the telnet server functionality of the test device)


Upgrade to python 3.11 on Ubuntu server
sudo apt install python3.11
python3 -V will still show 3.10, to modify this
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 1
sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 2
sudo update-alternatives --config python3
choose 2 for pyhton3.11

sudo apt install git
sudo apt install sshpass (for scp tests)
sudo apt install openssh-server (for ssh tests)
sudo apt install telnetd (for telnet tests)
Install VS Code or IDE of choice?
sudo snap install --classic code

cd Documents
git clone https://github.com/merlit64/mav6.git
cd mav6

sudo apt install python3-pip
sudo apt install python3.11-venv
python3 -m venv ../mav6-env
source ../mav6-env/bin/activate
pip install -r requirements.txt


if using vscode
code .
may want to install the Python Extension Pack


copy sample_secrets.py file to secrets.py
update TEST_DEVICE to the proper IPv4 or IPv6 address (depending on which you intend to test, required)
update TEST_DEVICE HOSTNAME to the hostname of the test device (required)
update SNMP_USER, AUTH_KEY and PRIV_KEY if you intend to test SNMP v3 (optional)
update COM_RO and COM_RW if you intend to test SNMP v2 (optional)
update CLI_USER and USER_PASS to allow mav6 to attach to the test_device via SSH (required)
update MAV6_IPV4 and MAV6_IPV6 MAV6_USER and MAV6_PASS (required)
update NTP_TEST_SERVER, this can be any ntp server as long as it is accessible by the test box, it must match the ip version being used

update test_configuration.py to indicate which tests will be performed

