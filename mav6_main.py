######## IMPORTED LIBRARIES ########
from termcolor import colored
from secrets import *

# pyATS
from pyats.topology import loader

# for ping test
import os

# for SNMP tests
from pysnmp.hlapi import *
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.carrier.asynsock.dgram import udp6
import socket




######## FUNCTIONS ########

def ping_host(ipaddress):
    response = os.system("ping -c 1 " + ipaddress)
    if (response == 0):
        print("Reachability Check passed...")
        return True
    else:
        return False

# SNMP Test Functions

class Udp6TransportTarget(cmdgen.UdpTransportTarget):
    # SNMP over IPv6 tweaks
    transportDomain = udp6.domainName

    def __init__(self, transportAddr, timeout=1, retries=5):
        self.transportAddr = (
            socket.getaddrinfo(transportAddr[0], transportAddr[1],
                               socket.AF_INET6,
                               socket.SOCK_DGRAM,
                               socket.IPPROTO_UDP)[0][4]
            )
        self.timeout = timeout
        self.retries = retries

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
    if (action == "read" and version == "v2"):
        iterator = getCmd(SnmpEngine(),
                        CommunityData(community),
                        UdpTransportTarget((ip, port)),
                        ContextData(),
                        ObjectType(ObjectIdentity(module, parent, suffix)))

    elif ( action == "write" and version == "v2" ):
        iterator = setCmd(SnmpEngine(),
                        CommunityData(community),
                        UdpTransportTarget((ip, port)),
                        ContextData(),
                        ObjectType(ObjectIdentity(module, parent, suffix), mib_value))

    elif ( action == "read" and version == "v3" ):
        iterator = getCmd(SnmpEngine(),
           UsmUserData(userName=userName, authKey=authKey, privKey=privKey, 
                       authProtocol=authProtocol, privProtocol=privProtocol),
           UdpTransportTarget((ip, port)),
           ContextData(),
           ObjectType(ObjectIdentity(module, parent, suffix)))

    elif ( action == "Write" and version == "v3" ):
        iterator = setCmd(SnmpEngine(),
            UsmUserData(userName=userName, authKey=authKey, privKey=privKey, 
                       authProtocol=authProtocol, privProtocol=privProtocol),
            UdpTransportTarget((ip, port)),
            ContextData(),
            ObjectType(ObjectIdentity(module, parent, suffix), mib_value))

    else:
        print('Incorrect syntax for action (use "read" or "write") or version (use "v2" or "v3").')
        exit()

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

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


######## MAIN PROGRAM ########

# Note: ALL comments are made from the perspective of the test device
# I.E. Telnet server test means the Test device is acting as the TFTP Server


### SERVER TESTS ###

# Ping Server Test
ping_host(TEST_DEVICE)
print(colored("Testing termcolor", "red"))


# Telnet Server Test
# Jay


# SSH Server Test
# Jay
testbed = loader.load('pyATS/testbed_ssh.yaml')

device = testbed.devices['campus1-bn1']

device.connect()

device.execute('show version')


# SCP Server Test
# Jay


# TFTP Server Test


# HTTP Server Test


# HTTPS Server Test


# SNMP v2 Read Test
# Paul
snmp_call( TEST_DEVICE, 'IF-MIB', 'ifAdminStatus', 5, version = "v2", action = "read", community=COM_RO )


# SNMP v2 Write Test
# Paul
snmp_call( TEST_DEVICE, 'IF-MIB', 'ifAdminStatus', 5, mib_value="up", version = "v2", action = "write", community=COM_RW )


# SNMP v3 Read Test
# Paul
snmp_call( TEST_DEVICE, 'IF-MIB', 'ifInOctets', 1, version = "v3", action = "read", userName=SNMP_USER,
          authKey=AUTH_KEY, privKey=PRIV_KEY  )

'''
iterator = ( getCmd(SnmpEngine(),
           UsmUserData(userName=SNMP_USER, authKey=AUTH_KEY, privKey=PRIV_KEY, 
                       authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol),
           UdpTransportTarget((TEST_DEVICE, 161)),
           ContextData(),
           ObjectType(ObjectIdentity('IF-MIB', 'ifInOctets', 1)))
)

errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

if errorIndication:
    print(colored("SNMPv3 Read Failed.  Error message:", "red"))
    print(errorIndication)
elif errorStatus:
    print(colored("SNMPv3 Read Failed.  Message:", "red"))
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
else:
    for varBind in varBinds:
        print(colored("SNMPv3 Read Successful.  IF-MIB ifInOctets read, results below:", "green"))
        print(' = '.join([x.prettyPrint() for x in varBind]))
print('\n')
'''

# SNMP v3 Write Test
# Paul

iterator = ( setCmd(SnmpEngine(),
            UsmUserData(userName=SNMP_USER, authKey=AUTH_KEY, privKey=PRIV_KEY, 
                       authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol),
            UdpTransportTarget((TEST_DEVICE, 161)),
            ContextData(),
            ObjectType(ObjectIdentity('IF-MIB', 'ifAdminStatus', 6), "down"))
)

errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

if errorIndication:
    print(colored("SNMPv3 Write Failed.  Error message:", "red"))
    print(errorIndication)
elif errorStatus:
    print(colored("SNMPv3 Write Failed.  Message:", "red"))
    print('%s at %s' % (errorStatus.prettyPrint(),
                        errorIndex and varBinds[int(errorIndex) - 1][0] or '?'))
else:
    for varBind in varBinds:
        print(colored("SNMPv3 Write Successful.  IF-MIB ifInOctets read, results below:", "green"))
        print(' = '.join([x.prettyPrint() for x in varBind]))
print('\n')


# NTP v4 Server Test


# DHCP Server Test



### CLIENT TESTS ###

# Ping Client Test


# Telnet Client Test


# SSH Client Test


# DNS Client Test


# SCP client Test


# TFTP client Test


# HTTP client Test


# HTTPS client Test


# SNMP v2 Trap Test


# SNMP v3 Trap Test


# NTP v4 Client Test


# DHCP Client Test


# Syslog Client Test


# Streaming Telemetry Test


# Netflow Tests


# TACACS+ Test


# RADIUS Test

