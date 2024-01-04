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
