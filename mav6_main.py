######## IMPORTED LIBRARIES ########
from time import sleep
from termcolor import colored
from secrets_1 import *
from test_configuration import *
import ipaddr

# pyATS
from pyats.topology import loader
from pyats.utils.fileutils import FileUtils

# for ping test
import os

# for SNMP tests
from pysnmp.hlapi import *
from pysnmp.carrier.asynsock.dgram import udp6
import socket

# for NTP test
import ntplib
from time import ctime

# for file transfer tests
from genie.libs.filetransferutils import FileServer

# for HTTP tests
import requests

# for TFTP tests
from tftpy import TftpClient
from tftpy import TftpServer

######## FUNCTIONS #######

def ping_host(ip):
    try:
        ip2 = ipaddr.IPAddress(ip)
    except:
        # This is not an IPv4 or an IPv6 address
        print(colored("IP address is malformed... Exiting", "red"))
        exit()
    if ( ip2.version == 4 ):
        response = os.system("ping -c 1 " + ip)
    else:
        response = os.system("ping6 -c 1 " + ip)
    if (response == 0):
        print("Reachability Check passed...")
        return True
    else:
        return False

    
# pyATS Connection Function
# device - hostname of device being tested
# protocol - connection protocol being tested (telnet or ssh)
# command - command used to test connection
def connect_host(device = '', protocol = '', command = ' '):
    testbed = loader.load('pyATS/testbed.yaml')

    test = testbed.devices[device]

    test.connect(via = protocol)

    if (not command.isspace):
        device.execute(command)

    return test
    
# HTTP Test Function
# verify - uses HTTPS if set to false
def http_test(ip= '', verify = True):
    try:
        ip2 = ipaddr.IPAddress(ip)
        print(colored(("IP address is good.  Version is IPv%s" % ip2.version), "green"))
    except:
        # This is not an IPv4 or an IPv6 address
        print(colored("IP address is malformed... Exiting", "red"))
        exit()
    
    if verify:
        http_string, http_print = "http://", "HTTP"
    else:
        http_string, http_print = "https://", "HTTPS"
    
    if ip2.version == 6:
        url = http_string + "[{0}]".format(ip2.compressed)  
    else:
        url = http_string + ip2.compressed
        
    r = requests.get(url, verify = verify)
    code = r.status_code
    if code == 200:
        print(colored((http_print + " Test Successful (Status code 200)\n"), "green"))
    else:
        print(colored((http_print + " Test Failed (Status code " + code + ")\n"), "red"))


# SNMP Test Functions

class Udp6TransportTarget(UdpTransportTarget):
    # SNMP over IPv6 tweaks
    transportDomain = udp6.domainName

    def __init__(self, transportAddr, timeout=1, retries=5, tagList=b'', iface=''):
        self.transportAddr = (
            socket.getaddrinfo(transportAddr[0], transportAddr[1],
                               socket.AF_INET6,
                               socket.SOCK_DGRAM,
                               socket.IPPROTO_UDP)[0][4]
            )
        self.timeout = timeout
        self.retries = retries
        self.tagList = tagList
        self.iface = iface

    def openClientMode(self):
        self.transport = udp6.Udp6SocketTransport().openClientMode()
        return self.transport
    
def snmp_call( ip, module, parent, suffix, mib_value=None, port= 161, version = "v2", action = "read", 
              community="public", userName=None, authKey=None, privKey=None,  
              authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol ):
    # This function places an SNMP read or write call using snmp v2 or v3 depending on the parameters
    # ip - is the address of the device to be tested
    # module - SNMP module, i.e. SNMPv2-MIB or IF-MIB
    # parent - SNMP parent i.e. SysDescr or ifAdminStatus 
    # suffix - if there are multiple modult/parents they are typically numbered with a suffix starting with 1
    # mib_value - for SNMP writes, a value to change the MIB to
    # port - SNMP UDP port number which is typicall 161
    # version - Either "v2" or "v3", "v2" is the default
    # action - Either "read" or "write", "read" is the default
    # community - Only required for SNMP v2, "public by default"
    # username - Only required for SNMP v3
    # authKey - Only required for SNMPv3... it's the authentication key
    # privKey - Only required for SNMPv3... It's the encryption private key
    # authProtocol - Only required for SNMPv3... It's the authentication protocol, None, MD5 or a SHA algorithm
    # privProtocol -  Only required for SNMPv3... It's the encryption protocol, DES, AES128, 192, 256, etc.
    
    # Check for IPv4 or IPv6 address
    try:
        ip2 = ipaddr.IPAddress(ip)
        print(colored(("IP address is good.  Version is IPv%s" % ip2.version), "green"))
    except:
        # This is not an IPv4 or an IPv6 address
        print(colored("IP address is malformed... Exiting", "red"))
        exit()

    # Build SNMP get or set command
    if (action == "read" and version == "v2"):
        iterator = getCmd(SnmpEngine(),
                        CommunityData(community),
                        UdpTransportTarget((ip, port)) if ip2.version == 4 else Udp6TransportTarget((ip, port)),
                        ContextData(),
                        ObjectType(ObjectIdentity(module, parent, suffix)))

    elif ( action == "write" and version == "v2" ):
        iterator = setCmd(SnmpEngine(),
                        CommunityData(community),
                        UdpTransportTarget((ip, port)) if ip2.version == 4 else Udp6TransportTarget((ip, port)),
                        ContextData(),
                        ObjectType(ObjectIdentity(module, parent, suffix), mib_value))

    elif ( action == "read" and version == "v3" ):
        iterator = getCmd(SnmpEngine(),
           UsmUserData(userName=userName, authKey=authKey, privKey=privKey, 
                       authProtocol=authProtocol, privProtocol=privProtocol),
           UdpTransportTarget((ip, port)) if ip2.version == 4 else Udp6TransportTarget((ip, port)),
           ContextData(),
           ObjectType(ObjectIdentity(module, parent, suffix)))

    elif ( action == "write" and version == "v3" ):
        iterator = setCmd(SnmpEngine(),
            UsmUserData(userName=userName, authKey=authKey, privKey=privKey, 
                       authProtocol=authProtocol, privProtocol=privProtocol),
            UdpTransportTarget((ip, port)) if ip2.version == 4 else Udp6TransportTarget((ip, port)),
            ContextData(),
            ObjectType(ObjectIdentity(module, parent, suffix), mib_value))

    else:
        print('Incorrect syntax for action (use "read" or "write") or version (use "v2" or "v3").')
        exit()

    # Execute the command and capture any errors
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    # Display error or Success messages
    if errorIndication:  # SNMP engine errors
        print(colored("SNMP" + version + " " + action + " Failed.  Error message:", "red"))
        print(errorIndication)
    else:
        if errorStatus:  # SNMP agent errors
            print(colored("SNMP" + version + " " + action + " Failed.  Error message:", "red"))
            print('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex)-1] if errorIndex else '?'))
        else:
            for varBind in varBinds:  # SNMP response contents
                print(colored("SNMP" + version + " " + action + " Succeeded!.  Results are below:", "green"))
                print(' = '.join([x.prettyPrint() for x in varBind]))
    print('\n')
    return 1

def tftp_download( ip, port=69, filename='test.cfg' ):

    try:
        ip2 = ipaddr.IPAddress(ip)
    except:
        # This is not an IPv4 or an IPv6 address
        print(colored("IP address is malformed... Exiting", "red"))
        exit()

    if ( ip2.version == 4 ):
        print(colored("Attempting TFTP download via IPv4", "yellow"))        
        client = TftpClient(ip, port)
    else:
        print(colored("Attempting TFTP download via IPv6", "yellow"))
        client = TftpClient(ip, port, af_family=socket.AF_INET6 )

    try:
        # CHECK HERE TO SEE IF FILE IS ALREADY LOCAL
        if os.path.isfile(filename):
            print("tftp test download file exists locally... deleting")
            os.remove(filename)
            sleep(1)
        else:
            print("tftp test download file does not exist locally... continuing")
        client.download(filename, filename)
        # CHECK HERE TO SEE IF FILE IS LOCAL
        if os.path.isfile(filename):
            print(colored("TFTP Download success!!!", "green"))
        else:
            print(colored("TFTP Download failed", "red"))
    except:
        print(colored("TFTP Download failed", "red"))


######## MAIN PROGRAM ########

# Note: ALL comments are made from the perspective of the test device
# I.E. Telnet server test means the Test device is acting as the TFTP Server


### SERVER TESTS ###

print("Executing Server Tests (where test box acts as the server):\n\n")


# Ping Server Test
if PING_SERVER:
    ping_host(TEST_DEVICE)


# Telnet Server Test
if TELNET_SERVER:
    connect_host('mgmt', 'telnet')

# SSH Server Test
if SSH_SERVER:
    connect_host('mgmt', 'ssh')


# SCP Server Test
if SCP_SERVER:
    command = 'sshpass -p "' + PRIV_KEY + '" scp test.txt ' + CLI_USER + '@[' + TEST_DEVICE + ']:flash:/test.txt'
    os.system(command)
    print(colored(("SCP Server Test Attempted"), "green"))

# TFTP Server Test
if TFTP_SERVER:
    tftp_download(TEST_DEVICE, port=69, filename='test.cfg')


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
# Linux Server
# Python Script
# IOSXE Device
# pyATS https://developer.cisco.com/docs/genie-docs/

# Telnet Client Test
# Linux Server
# Python Script
# IOSXE Device
# pyATS Maybe this? description doesn't seem right: https://developer.cisco.com/docs/genie-docs/ 

# SSH Client Test
# Linux Server
# Python Script
# IOSXE Device
# pyATS Maybe this? description doesn't seem right: https://developer.cisco.com/docs/genie-docs/


# DNS Client Test
# Linux Server
# Windows Server
# maybe https://developer.cisco.com/docs/genie-docs/

# SCP client Test
# Linux Server
# IOSXE Device

# TFTP client Test
test_dev = connect_host('mgmt', 'ssh')
test_dev.api.copy_to_device(protocol='tftp', server='tftpserver', 
                            remote_path='test.txt', local_path='flash:/')

# HTTP client Test
# Linux Server
# Windows Server
# IOSXE Device
# pyATS https://developer.cisco.com/docs/genie-docs/%20opy or https://developer.cisco.com/docs/genie-docs/
'''testbed = loader.load('pyATS/testbed.yaml')

test = testbed.devices["C8000V"]

test.connect(via = 'ssh')

test.api.copy_to_device(protocol='tftp',
                        server='filesvr',
                        remote_path='test.cfg',
                        local_path = 'flash:/')'''


# HTTPS client Test
# Linux Server
# Windows Server
# # IOSXE Device


# SNMP v2 Trap Test
# Python Library

# SNMP v3 Trap Test
# Python Library?

# NTP v4 Client Test
# Linux Server
# Python Script?
# IOSXE Device
# pyATS https://developer.cisco.com/docs/genie-docs/
# https://developer.cisco.com/docs/genie-docs/


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
