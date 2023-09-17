######## IMPORTED LIBRARIES ########
from termcolor import colored
from secrets_1 import *
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

######## MAIN PROGRAM ########

# Note: ALL comments are made from the perspective of the test device
# I.E. Telnet server test means the Test device is acting as the TFTP Server


### SERVER TESTS ###

# Ping Server Test
ping_host(TEST_DEVICE)


# Telnet Server Test
# Jay
#connect_host('mgmt', 'telnet')

# SSH Server Test
# Jay
#connect_host('mgmt', 'ssh')


# SCP Server Test

testbed = loader.load('pyATS/testbed.yaml')

test = testbed.devices["mgmt"]

test.connect(via = 'ssh')

test.api.copy_from_device(protocol='tftp',
                        server='scpserver',
                        remote_path='',
                        local_path = 'flash:/test.cfg')

# TFTP Server Test


# HTTP Server Test


# HTTPS Server Test


# SNMP v2 Read Test
# Paul
# snmp_call( TEST_DEVICE, 'IF-MIB', 'ifAlias', 1, version = "v2", action = "read", community=COM_RO )


# SNMP v2 Write Test
# Paul
#snmp_call( TEST_DEVICE, 'SNMPv2-MIB', 'sysContact', 0, mib_value="mav6 snmpv2test worked", version = "v2", action = "write", community=COM_RW )


# SNMP v3 Read Test
# Paul
#snmp_call( TEST_DEVICE, 'IF-MIB', 'ifInOctets', 1, version = "v3", action = "read", 
          #userName=SNMP_USER, authKey=AUTH_KEY, privKey=PRIV_KEY  )


# SNMP v3 Write Test
# Paul
#snmp_call( TEST_DEVICE, 'IF-MIB', 'ifAlias', 1, mib_value="mav6", version = "v3", action = "write", 
          #userName=SNMP_USER, authKey=AUTH_KEY, privKey=PRIV_KEY  )


# NTP v4 Server Test
# Jay

#c = ntplib.NTPClient()
#response = c.request(TEST_DEVICE, version = 4)
#print("NTP TIME IS " + ctime(response.tx_time) + " FROM NTP SERVER " + TEST_DEVICE)

# DHCP Server Test



### CLIENT TESTS ###

# Ping Client Test
# Linux Server
# Python Script
# IOSXE Device

# Telnet Client Test
# Linux Server
# Python Script
# IOSXE Device

# SSH Client Test
# Linux Server
# Python Script
# IOSXE Device


# DNS Client Test
# Linux Server
# Windows Server


# SCP client Test
# Linux Server
# IOSXE Device


# TFTP client Test
# Linux Server
# IOSXE Device


# HTTP client Test
# Linux Server
# Windows Server
# IOSXE Device


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


# DHCP Client Test
# Linux Server
# Windows Server

# Syslog Client Test
# Linux Server
# Python Script
# IOSXE Device


# Streaming Telemetry Test


# Netflow Tests
# Linux Server Netflow collectors
# Python Script netflow collector


# TACACS+ Test
# ISE

# RADIUS Test
# ISE
