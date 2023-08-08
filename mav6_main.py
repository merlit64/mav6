######## IMPORTED LIBRARIES ########
from termcolor import colored

# pyATS
from pyats.topology import loader

# for ping test
import os

# for SNMP tests
from pysnmp.hlapi import *
from pysnmp.entity.rfc3413.oneliner import cmdgen
from pysnmp.carrier.asynsock.dgram import udp6
import socket


######## MACROS ########
TEST_DEVICE = "8.8.8.8"


######## FUNCTIONS ########

def ping_host(ipaddress):
    response = os.system("ping -c 1 " + ipaddress)
    if (response == 0):
        print("Reachability Check passed...")
        return True
    else:
        return False

# SNMP Test Functions

# SNMP over IPv6 tweaks
class Udp6TransportTarget(cmdgen.UdpTransportTarget):
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
iterator = getCmd(SnmpEngine(),
                  CommunityData('***REMOVED***'),
                  UdpTransportTarget(('***REMOVED***', 161)),
                  ContextData(),
                  ObjectType(ObjectIdentity('IF-MIB', 'ifAdminStatus', 5)))

errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

if errorIndication:  # SNMP engine errors
    print(colored("SNMPv2 Read Failed.  Error message:", "red"))
    print(errorIndication)
else:
    if errorStatus:  # SNMP agent errors
        print(colored("SNMPv2 Read Failed.  Error message:", "red"))
        print('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex)-1] if errorIndex else '?'))
    else:
        for varBind in varBinds:  # SNMP response contents
            print(colored("SNMPv2 Read Successful.  IF-MIB ifAdminStatus read, results below:", "green"))
            print(' = '.join([x.prettyPrint() for x in varBind]))
print('\n')

# SNMP v2 Write Test
# Paul

iterator = setCmd(SnmpEngine(),
                  CommunityData('***REMOVED***rw'),
                  UdpTransportTarget(('2005:1117::1', 161)),
                  ContextData(),
                  ObjectType(ObjectIdentity('IF-MIB', 'ifAdminStatus', 5), "down"))

errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

if errorIndication:  # SNMP engine errors
    print(colored("SNMPv2 Write Failed.  Error message:", "red"))
    print(errorIndication)
else:
    if errorStatus:  # SNMP agent errors
        print(colored("SNMPv2 Write Failed.  Message:", "red"))
        print('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex)-1] if errorIndex else '?'))
    else:
        for varBind in varBinds:  # SNMP response contents
            print(colored("SNMPv2 Write Successful.  IF-MIB ifAdminStatus write, results below:", "green"))
            print(' = '.join([x.prettyPrint() for x in varBind]))
print('\n')



# SNMP v3 Read Test
# Paul
iterator = ( getCmd(SnmpEngine(),
           UsmUserData(userName="***REMOVED***", authKey='***REMOVED***', privKey='***REMOVED***', 
                       authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol),
           UdpTransportTarget(('***REMOVED***', 161)),
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


# SNMP v3 Write Test
# Paul

iterator = ( setCmd(SnmpEngine(),
            UsmUserData(userName="***REMOVED***", authKey='***REMOVED***', privKey='***REMOVED***', 
                       authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol),
            UdpTransportTarget(('***REMOVED***', 161)),
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

