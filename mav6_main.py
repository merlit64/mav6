######## IMPORTED LIBRARIES ########
### STANDARD LIBRARIES ###
from multiprocessing import Process, Queue
from time import sleep, ctime
import os
#import shutil
#import ssl
#import socket
#import certifi

### LOCAL FILES ###
from secrets_1 import *
from test_configuration import *
from server import *
from client import *
from mav6utils import *
from embedded_fs import *

### PYPI LIBRARIES ###
from termcolor import colored
#import ipaddr

# pyATS
#from pyats.topology import loader
#from pyats.utils.fileutils import FileUtils
#from genie.libs.sdk.apis.iosxe import utils
#from genie.libs.sdk.apis.iosxe.ntp.configure import *

# for ping test
import os

# for SNMP tests
#from pysnmp.hlapi import *
#from pysnmp.carrier.asynsock.dgram import udp, udp6
#from pysnmp.entity import engine, config
#from pysnmp.entity.rfc3413 import ntfrcv, context, cmdrsp
#from pysnmp.proto import rfc1902

# for NTP test
import ntplib

# for HTTP tests
#import requests

# for TFTP tests
#from tftpy import TftpClient


# Certificate functions
#from OpenSSL import SSL, crypto

######## FUNCTIONS #######


######## MAIN PROGRAM ########

# Note: ALL comments are made from the perspective of the test device
# I.E. Telnet server test means the Test device is acting as the TFTP Server

#os.chdir('keys_and_certs')
#get fingerprint of rootCA.crt
#command = 'openssl x509 in rootCA.crt -noout -fingerprint >> fingerprint.txt'
#os.system(command)


### SERVER TESTS ###
#ca_buildca('10.112.1.106')

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

print("Executing Client Tests (where test box acts as the client):\n\n")

### CLIENT TESTS ###

# Ping Client Test
if PING_CLIENT:
    ping_client('mgmt', device_to_ping=LOCAL_DEVICE)


# Telnet Client Test
# Linux Server
# Python Script
# IOSXE Device
# pyATS Maybe this? description doesn't seem right: https://developer.cisco.com/docs/genie-docs/ 
if TELNET_CLIENT:
    telnet_client('C8000V', 'mgmt', REMOTE_SERVER, CLI_USER, USER_PASS)
    
# SSH Client Test
# Linux Server
# Python Script
# IOSXE Device
# pyATS Maybe this? description doesn't seem right: https://developer.cisco.com/docs/genie-docs/
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
    mav6_ip = MAV6_IPV4 if ip_version(TEST_DEVICE) == 4 else MAV6_IPV6
    result = file_transfer_client(protocol='tftp', test_device_hostname=TEST_DEVICE_HOSTNAME, 
                                  test_device_ip=TEST_DEVICE, mav6_ip=mav6_ip)
    if (result):
        print(colored("TFTP Client Test Successful\n\n", "green"))
    else:
        print(colored("TFTP Client Test Failed\n\n", "red"))

# FTP Client test
if FTP_CLIENT:
    mav6_ip = MAV6_IPV4 if ip_version(TEST_DEVICE) == 4 else MAV6_IPV6
    result = file_transfer_client(protocol='ftp', test_device_hostname=TEST_DEVICE_HOSTNAME, 
                                  test_device_ip=TEST_DEVICE, mav6_ip=mav6_ip)
    if (result):
        print(colored("FTP Client Test Successful\n\n", "green"))
    else:
        print(colored("FTP Client Test Failed\n\n", "red"))

# HTTP client Test
if HTTP_CLIENT:
    mav6_ip = MAV6_IPV4 if ip_version(TEST_DEVICE) == 4 else MAV6_IPV6
    result = file_transfer_client(protocol='http', test_device_hostname=TEST_DEVICE_HOSTNAME, 
                                  test_device_ip=TEST_DEVICE, mav6_ip=mav6_ip)
    if (result):
        print(colored("HTTP Client Test Successful\n\n", "green"))
    else:
        print(colored("HTTP Client Test Failed\n\n", "red"))


# HTTPS client Test
if HTTPS_CLIENT:
    mav6_ip = MAV6_IPV4 if ip_version(TEST_DEVICE) == 4 else MAV6_IPV6
    result = file_transfer_client(protocol='https', test_device_hostname=TEST_DEVICE_HOSTNAME, 
                                  test_device_ip=TEST_DEVICE, mav6_ip=mav6_ip,
                                  ca_directory=CA_DIRECTORY)
    if (result):
        print(colored("HTTPS Client Test Successful\n\n", "green"))
    else:
        print(colored("HTTPS Client Test Failed\n\n", "red"))


# SNMP v2 Trap Test
if SNMPV2_TRAP:
    mav6_ip = MAV6_IPV4 if ip_version(TEST_DEVICE) == 4 else MAV6_IPV6
    result = snmp_trap_client(snmp_version=2, comm_uname=COM_RW, mav6_ip=mav6_ip, 
                              test_device_hostname=TEST_DEVICE_HOSTNAME, test_device_ip=TEST_DEVICE)

    # Print Test results to screen
    if (result):
        print(colored("SNMPv2 Trap Test Successful\n\n", "green"))
    else:
        print(colored("SNMPv2 Trap Test Failed\n\n", "red"))


# SNMP v3 Trap Test
if SNMPV3_TRAP:
    mav6_ip = MAV6_IPV4 if ip_version(TEST_DEVICE) == 4 else MAV6_IPV6
    result = snmp_trap_client(snmp_version=3, comm_uname=COM_RW, mav6_ip=mav6_ip, 
                              test_device_hostname=TEST_DEVICE_HOSTNAME, test_device_ip=TEST_DEVICE)

    # Print Test results to screen
    if (result):
        print(colored("SNMPv2 Trap Test Successful\n\n", "green"))
    else:
        print(colored("SNMPv2 Trap Test Failed\n\n", "red"))

    
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
