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
from ca import *

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
    # Connect to test device and check for test file on flash
    device = connect_host( device=TEST_DEVICE_HOSTNAME, protocol='ssh')
    if(file_on_flash(device, filename='test.txt')):
        del_from_flash(device, 'test.txt')
    if (ip_version(TEST_DEVICE) == 4):
        tftp_server_process = Process(target=start_server, name='tftpserver', 
                                      args=('tftp', MAV6_IPV4,))
    else:
        tftp_server_process = Process(target=start_server, name='tftpserver', 
                                      args=('tftp', MAV6_IPV6,))


    print('starting tftp server process')
    tftp_server_process.start()
    sleep(5)

    if (ip_version(TEST_DEVICE) == 4):
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME, device_protocol='ssh',
                                 server_ip=MAV6_IPV4, transfer_protocol='tftp')
    else:
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME, device_protocol='ssh',
                                 server_ip=MAV6_IPV6, transfer_protocol='tftp')


    # Check to see if file transfer was successful and print message
    if (file_on_flash(device, filename='test.txt')):
        print(colored("TFTP Client Test Successful", "green"))
    else:
        print(colored("TFTP Client Test Failed", "red"))
    
    sleep(2)
    tftp_server_process.kill()

# FTP Client test
if FTP_CLIENT:
    # Connect to test device and check for test file on flash
    device = connect_host( device=TEST_DEVICE_HOSTNAME, protocol='ssh')
    if(file_on_flash(device, filename='test.txt')):
        del_from_flash(device, 'test.txt')

    if (ip_version(TEST_DEVICE) == 4):
        ftp_server_process = Process(target=start_server, name='ftpserver', 
                                     args=('ftp',MAV6_IPV4,))
    else:
        ftp_server_process = Process(target=start_server, name='ftpserver', 
                                     args=('ftp',MAV6_IPV6,))
        
    print('starting ftp server process')
    ftp_server_process.start()
    sleep(5)

    if (ip_version(TEST_DEVICE) == 4):
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME, device_protocol='ssh',
                                    server_ip=MAV6_IPV4, transfer_protocol='ftp')
    else:
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME, device_protocol='ssh',
                                    server_ip=MAV6_IPV6, transfer_protocol='ftp')


    # Check to see if file transfer was successful and print message
    if (file_on_flash(device, filename='test.txt')):
        print(colored("FTP Client Test Successful", "green"))
    else:
        print(colored("FTP Client Test Failed", "red"))
    
    sleep(2)
    ftp_server_process.kill()

# HTTP client Test
if HTTP_CLIENT:
    # Connect to test device and check for test file on flash
    device = connect_host( device=TEST_DEVICE_HOSTNAME, protocol='ssh')
    if(file_on_flash(device, filename='test.txt')):
        del_from_flash(device, 'test.txt')

    print('starting http server process')
    if (ip_version(TEST_DEVICE) == 4):
        http_server_process = Process(target=start_server, name='httpserver', 
                                      args=('http', MAV6_IPV4,))
        http_server_process.start()
        sleep(5)
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME, device_protocol='ssh', 
                                     server_ip=MAV6_IPV4, transfer_protocol='http')
    else:
        http_server_process = Process(target=start_server, name='httpserver', 
                                      args=('http',MAV6_IPV6,))
        http_server_process.start()
        sleep(5)
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME,  device_protocol='ssh',
                                     server_ip=MAV6_IPV6, transfer_protocol='http')
    # Check to see if file transfer was successful and print message
    if (file_on_flash(device, filename='test.txt')):
        print(colored("HTTP Client Test Successful", "green"))
    else:
        print(colored("HTTP Client Test Failed", "red"))
    
    sleep(2)
    http_server_process.kill()


# HTTPS client Test
if HTTPS_CLIENT:
    # Connect to test device and check for test file on flash
    device = connect_host( device=TEST_DEVICE_HOSTNAME, protocol='ssh')
    if(file_on_flash(device, filename='test.txt')):
        del_from_flash(device, 'test.txt')

    # Create CA on Mav6 and create a signed cert for Mav6 https server
    ca_create_directory(ca_directory=CA_DIRECTORY)
    ca_build_ca(ca_directory=CA_DIRECTORY)
    ca_create_cert(ca_directory=CA_DIRECTORY, key_name='server')
    #ca_build_server_cert(SERVER_CSR_CONF, SERVER_CERT_CONF, 'server', CA_DIRECTORY)

    # Start Server, server will use cert stored in CA directory
    print('starting https server process')
    if (ip_version(TEST_DEVICE) == 4):
        https_server_process = Process(target=start_server, name='httpsserver', 
                                       args=('https',MAV6_IPV4,))
    else:
        https_server_process = Process(target=start_server, name='httpsserver', 
                                       args=('https',MAV6_IPV6,))

    https_server_process.start()
    sleep(5)

    # Add a trustpoint in the router that trusts the mav6 CA
    rtr_add_trustpoint(device, CA_DIRECTORY)
    rtr_authenticate_rootca(device, CA_DIRECTORY)

    # Try the copy https: flash: command 
    if (ip_version(TEST_DEVICE) == 4):
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME,  device_protocol='ssh',
                                     server_ip=MAV6_IPV4, transfer_protocol='https')
    else:
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME,  device_protocol='ssh',
                                     server_ip=MAV6_IPV6, transfer_protocol='https')

    # Check to see if file transfer was successful and print message
    if (file_on_flash(device, filename='test.txt')):
        print(colored("HTTPS Client Test Successful", "green"))
    else:
        print(colored("HTTPS Client Test Failed", "red"))
    sleep(2)

    https_server_process.kill()


# SNMP v2 Trap Test
if SNMPV2_TRAP:
    if (ip_version(TEST_DEVICE) == 4):
        mav6_ip = MAV6_IPV4
    else:
        mav6_ip = MAV6_IPV6

    q = Queue()
    snmp_trap_receiver_process = Process(target=snmp_start_trap_receiver, name='snmptrapreceiver', 
                                         args=(q,2, mav6_ip,162,COM_RW))

    print('starting snmpv2 trap receiver process')
    snmp_trap_receiver_process.start()
    sleep(5)
    # Below sends a test trap from mav6 to mav6 trap receiver, leave commented unless testing
    #snmp_trap_send(destination=mav6_ip, port=162, snmp_version=2)
    
    # Configure TEST_DEVICE to send SNMP traps to trap receiver
    device = connect_host(TEST_DEVICE_HOSTNAME, 'ssh')
    device.configure ('snmp-server host ' + mav6_ip + ' traps version 2c ' + COM_RW + \
                      ' udp-port 162 config\n' )

    sleep(5)    

    # Check the queue created by the SNMP receiver for a trap sent by TEST_DEVICE
    received_snmp = False
    while(not q.empty()):
        message = q.get()
        if('my system' in message):
            print('SNMPv3 message arrived at receiver from snmp_trap_send') 
        elif('netconf' in message):
            print('SNMPv3 message arrived at receiver from TEST_DEVICE')
            received_snmp = True
        else:
            # Unknown SNMP sender
            pass 

    # Print Test results to screen
    if (received_snmp):
        print(colored("SNMPv3 Trap Test Successful", "green"))
    else:
        print(colored("SNMPv3 Trap Test Failed", "red"))


    sleep(2)
    snmp_trap_receiver_process.kill()

# SNMP v3 Trap Test
if SNMPV3_TRAP:
    if (ip_version(TEST_DEVICE) == 4):
        mav6_ip = MAV6_IPV4
    else:
        mav6_ip = MAV6_IPV6

    q = Queue()
    snmp_trap_receiver_process = Process(target=snmp_start_trap_receiver, name='snmptrapreceiver', 
                                        args=(q,3, mav6_ip,162,))

    print('starting snmpv3 trap receiver process')
    snmp_trap_receiver_process.start()
    sleep(5)
    # Below sends a test trap from mav6 to mav6 trap receiver, leave commented unless testing
    snmp_trap_send(destination=mav6_ip, port=162, snmp_version=3)

    # Configure TEST_DEVICE to send SNMP traps to trap receiver
    device = connect_host(TEST_DEVICE_HOSTNAME, 'ssh')
    device.configure ('snmp-server group mav6group v3 noauth\n' + \
                        'snmp-server user mav6user mav6group v3\n' + \
                        'snmp-server enable traps\n' + \
                        'snmp-server host ' + mav6_ip + ' traps version 3 noauth mav6user\n'
                        )
    sleep(5) 

    # Check the queue created by the SNMP receiver for a trap sent by TEST_DEVICE
    received_snmp = False
    while(not q.empty()):
        message = q.get()
        if('my system' in message):
            print('SNMPv3 message arrived at receiver from snmp_trap_send') 
        elif('netconf' in message):
            print('SNMPv3 message arrived at receiver from TEST_DEVICE')
            received_snmp = True
        else:
            # Unknown SNMP sender
            pass 

    # Print Test results to screen
    if (received_snmp):
        print(colored("SNMPv3 Trap Test Successful", "green"))
    else:
        print(colored("SNMPv3 Trap Test Failed", "red"))

    
    sleep(2)
    snmp_trap_receiver_process.kill()

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
