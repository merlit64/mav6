######## IMPORTED LIBRARIES ########
### STANDARD LIBRARIES ###
from time import sleep, ctime
import os

### LOCAL FILES ###
from secrets import *
from test_configuration import *
from server import *
from client import *
from mav6utils import *
from embedded_fs import *

### PYPI LIBRARIES ###
from termcolor import colored

# for NTP test
import ntplib

######## MAIN PROGRAM ########

# Note: ALL comments are made from the perspective of the test device
# I.E. Telnet server test means the Test device is acting as the TFTP Server

# Ping Server Test
if PING_SERVER:
    result = ping_host(TEST_DEVICE)
    if (result):
        print(colored("Ping Server Test Success", "green"))
    else:
        print(colored("Ping Server Test Failed", "red"))

# Telnet Server Test
if TELNET_SERVER:
    device = connect_host(TEST_DEVICE_HOSTNAME, 'telnet')
    if (device == Null):
        print(colored("Telnet Server Test Failed", "red"))
    else:
        print(colored("Telnet Server Test Success", "green"))

# SSH Server Test
if SSH_SERVER:
    device = connect_host('mgmt', 'ssh')
    if (device == Null):
        print(colored("SSH Server Test Failed", "red"))
    else:
        print(colored("SSH Server Test Success", "green"))

# SCP Server Test
if SCP_SERVER:
    command = 'sshpass -p "' + PRIV_KEY + '" scp test.txt ' + CLI_USER + '@[' + TEST_DEVICE + ']:flash:/test.txt'
    os.system(command)
    print(colored(("SCP Server Test Attempted"), "green"))

# TFTP Server Test
if TFTP_SERVER:
    tftp_server_download(TEST_DEVICE, port=69, filename='test.cfg')

# HTTP Server Test
if HTTP_SERVER:
    http_test(TEST_DEVICE)

# HTTPS Server Test
if HTTPS_SERVER:
    http_test(TEST_DEVICE, verify=False)

# SNMP v2 Read Test
if SNMPV2_READ:
    snmp_call( TEST_DEVICE, 'IF-MIB', 'ifAlias', 1, version = "v2", action = "read", community=COM_RO )

# SNMP v2 Write Test
if SNMPV2_WRITE:
    snmp_call( TEST_DEVICE, 'SNMPv2-MIB', 'sysContact', 0, mib_value="mav6 snmpv2test worked", version = "v2", action = "write", community=COM_RW )

# SNMP v3 Read Test
if SNMPV3_READ:
    snmp_call( TEST_DEVICE, 'IF-MIB', 'ifInOctets', 1, version = "v3", action = "read", 
          userName=SNMP_USER, authKey=AUTH_KEY, privKey=PRIV_KEY  )

# SNMP v3 Write Test
if SNMPV3_WRITE:
    snmp_call( TEST_DEVICE, 'IF-MIB', 'ifAlias', 1, mib_value="mav6", version = "v3", action = "write", 
          userName=SNMP_USER, authKey=AUTH_KEY, privKey=PRIV_KEY  )

# NTP v4 Server Test
if NTP_SERVER:
    c = ntplib.NTPClient()
    response = c.request(TEST_DEVICE, version = 4)
    print("NTP TIME IS " + ctime(response.tx_time) + " FROM NTP SERVER " + TEST_DEVICE)

# DHCP Server Test


### CLIENT TESTS ###
print("Executing Client Tests (where test box acts as the client):\n\n")
mav6_ip = MAV6_IPV4 if ip_version(TEST_DEVICE) == 4 else MAV6_IPV6

# Ping Client Test
if PING_CLIENT:
    ping_client('mgmt', device_to_ping=LOCAL_DEVICE)

# Telnet Client Test
if TELNET_CLIENT:
    telnet_client('C8000V', 'mgmt', REMOTE_SERVER, CLI_USER, USER_PASS)
    
# SSH Client Test
if SSH_CLIENT:
    ssh_client('C8000V', 'mgmt', REMOTE_SERVER, CLI_USER, USER_PASS)

# DNS Client Test
# Linux Server
# Windows Server
# maybe https://developer.cisco.com/docs/genie-docs/

# SCP client Test
# Linux Server
# IOSXE Device

# TFTP client Test
if TFTP_CLIENT:
    result = file_transfer_client(protocol='tftp', test_device_hostname=TEST_DEVICE_HOSTNAME, 
                                  test_device_ip=TEST_DEVICE, mav6_ip=mav6_ip)
    if (result):
        print(colored("TFTP Client Test Successful\n\n", "green"))
    else:
        print(colored("TFTP Client Test Failed\n\n", "red"))

# FTP Client test
if FTP_CLIENT:
    result = file_transfer_client(protocol='ftp', test_device_hostname=TEST_DEVICE_HOSTNAME, 
                                  test_device_ip=TEST_DEVICE, mav6_ip=mav6_ip)
    if (result):
        print(colored("FTP Client Test Successful\n\n", "green"))
    else:
        print(colored("FTP Client Test Failed\n\n", "red"))

# HTTP client Test
if HTTP_CLIENT:
    result = file_transfer_client(protocol='http', test_device_hostname=TEST_DEVICE_HOSTNAME, 
                                  test_device_ip=TEST_DEVICE, mav6_ip=mav6_ip)
    if (result):
        print(colored("HTTP Client Test Successful\n\n", "green"))
    else:
        print(colored("HTTP Client Test Failed\n\n", "red"))

# HTTPS client Test
if HTTPS_CLIENT:
    result = file_transfer_client(protocol='https', test_device_hostname=TEST_DEVICE_HOSTNAME, 
                                  test_device_ip=TEST_DEVICE, mav6_ip=mav6_ip,
                                  ca_directory=CA_DIRECTORY)
    if (result):
        print(colored("HTTPS Client Test Successful\n\n", "green"))
    else:
        print(colored("HTTPS Client Test Failed\n\n", "red"))

# SNMP v2 Trap Test
if SNMPV2_TRAP:
    result = snmp_trap_client(snmp_version=2, comm_uname=COM_RW, mav6_ip=mav6_ip, 
                              test_device_hostname=TEST_DEVICE_HOSTNAME, test_device_ip=TEST_DEVICE)

    # Print Test results to screen
    if (result):
        print(colored("SNMPv2 Trap Test Successful\n\n", "green"))
    else:
        print(colored("SNMPv2 Trap Test Failed\n\n", "red"))

# SNMP v3 Trap Test
if SNMPV3_TRAP:
    result = snmp_trap_client(snmp_version=3, comm_uname=COM_RW, mav6_ip=mav6_ip, 
                              test_device_hostname=TEST_DEVICE_HOSTNAME, test_device_ip=TEST_DEVICE)

    # Print Test results to screen
    if (result):
        print(colored("SNMPv3 Trap Test Successful\n\n", "green"))
    else:
        print(colored("SNMPv3 Trap Test Failed\n\n", "red"))
    
# NTP v4 Client Test
# Linux Server
# Python Script?
# IOSXE Device
# pyATS https://developer.cisco.com/docs/genie-docs/
# https://developer.cisco.com/docs/genie-docs/
if NTP_CLIENT:
    ntp_client('C8000V', NTP_TEST_SERVER)

# DHCP Client Test
# Linux Server
# Windows Server

# Syslog Client Test
# Linux Server
# Python Script
# IOSXE Device
# pyATS: https://developer.cisco.com/docs/genie-docs/
# https://developer.cisco.com/docs/genie-docs/


# Streaming Telemetry Test


# Netflow Tests
# Linux Server Netflow collectors
# Python Script netflow collector


# TACACS+ Test
# ISE

# RADIUS Test
# ISE
