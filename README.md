# Managment Plane Application IPv6 (MAV6) #

MAV6 is an IPv6 testing application for Cisco networking devices. The objective of MAV6 is to verify compatibility of managment plane protocols in an IPv6 environment. MAV6 requires an Ubuntu test server to conduct testing on a IPv6 device. The test server and test device take turns acting as a server and client in each managment plane test. MAV6 produces a table of all test results as pass/fail. 
*Note: Test Device will be reconfigured during testing. Do not use a production device. Assume all configurations on the Test Device will be lost.


## Test Device Configuration ##

- Test Device Note: We need to talk generically, as we intend to support multiple Cisco OS's.  Currently we test IOS XE only, with NXOS on the roadmap.
  - configure a hostname
  - enable ssh with a username and password (required)
  - enable telnet with a Username and Password (required)
  - ip routing must be enable
  - ipv6 routing must be enable
  - if an ntp server is configured, remove that configuration


## Information Needed ##

- Test Device
  - hostname
  - IPv4 and IPv6 address
  - username
  - password (default and enable)
  - OS
- Ubuntu Server
  - IPv4 and IPv6 address
  - ubuntu server username and password
- Other
  - NTP server IPv4 and IPv6 addresses reachable by test device


## Ubuntu Server Configuration ##

- Install an Ubuntu 22.04 (python 3.10.12) Virtual Machine
- Give the server an IPv4 and and IPv6 address
- sudo apt update
- sudo apt upgrade
- Run software updater, if there are any updates, "Install Now", restart if requested
<!-- - Remote login: on -->
- sudo apt install git
- sudo apt install sshpass (for scp tests)
- sudo apt install telnetd telnet (for telnet tests)
- sudo apt install openssh-server (for ssh tests)

### Telnet Server Configuration ###

To enable ubuntu telnet server for ipv6, as well as default ipv4 support:
- sudo vi /etc/inetd.conf
- copy the line that start with "telnet     stream     tcp" and paste it below the existing line
- In the copy of the line, change tcp to tcp6
- save and quit
- systemctl restart inetd
- test by telneting to your self via ipv4 (ex: telnet 10.112.1.107), don't forget to exit when successful
- test by telneting to your self via ipv6 (ex: telnet 2001:db8::1), don't forget to exit when successful
- test by ssh-ing to your self via ipv4 (ex: ssh user1@10.112.1.107), don't forget to exit when successful
- test by ssh-ing to your self via ipv6 (ex: ssh user1@2001:db8::1), don't forget to exit when successful

### Clone Mav6 ###
- cd Documents
- git clone https://github.com/merlit64/mav6.git
- cd mav6

### Install Python3.11 and Virtual Environment ###

Starting with the Virtual Environment:
- sudo apt install python3.11
- sudo apt install python3-pip
- sudo apt install python3.11-venv
- python3.11 -m venv ../mav6-env
- source ../mav6-env/bin/activate
- python3 -V should show python3.11...
- pip install -r requirements.txt


### Oprional Development Environment ###
Install VS Code or IDE of choice, if desired.  An IDE is only needed if you want to debug:
- sudo snap install --classic code

if using vscode
- code .
- The moment you access your first .py file, VSCode will ask you to install the Python Extension Pack... do it
- Ctrl-Shift-P Select Python Interpreter... make sure you choose mav6-env
- Debug... create launch.json file and add "sudo": true to the end


## MAV6 Setup ##
- change ’sample_secrets.py’ to ’secrets_1.py’ and configure appropriately with authentication info
  - copy sample_secrets.py file to secrets.py
  - update TEST_DEVICE to the proper IPv4 or IPv6 address (depending on which you intend to test, required) 
  - update TEST_DEVICE HOSTNAME to the hostname of the test device (required)  Note: The hostname should already be configured on the test device
  - update SNMP_USER, AUTH_KEY and PRIV_KEY if you intend to test SNMP v3 (optional)
  - update COM_RO and COM_RW if you intend to test SNMP v2 (optional)
  - update CLI_USER and USER_PASS to allow mav6 to attach to the test_device via SSH (required)
  - update MAV6_IPV4 and MAV6_IPV6 MAV6_USER and MAV6_PASS (required)
  - update NTP_TEST_SERVER, this can be any ntp server as long as it is accessible by the test box, it must match the ip version being used
  
Note: These ipv4 and ipv6 addresses and the hostname, cli user/pass should already be configured on the TEST_DEVICE.  SNMP parameters will get pushed to the test device by Mav6 and need not be configured in advance. All required protocol servers for the tests are embedded on mav6 and will be spun up dynamically during the test that requires them with the exception of the NTP server.  The user need only provide an IPv4 and/or IPv6 address for an NTP server that the test device can reach.

- configure test_configuration to indicate which tests will execute
- Make sure there is communication between mav 6 and the test device via ipv4 and ipv6







