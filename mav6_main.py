######## IMPORTED LIBRARIES ########
from termcolor import colored

# pyATS
from pyats.topology import loader

# for ping test
import os

# for SNMP tests
from pysnmp.hlapi import *


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

# SNMP v2 Write Test
# Paul

iterator = setCmd(SnmpEngine(),
                  CommunityData('***REMOVED***rw'),
                  UdpTransportTarget(('***REMOVED***', 161)),
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
            print(colored("SNMPv2 Write Successful.  sysDescr MIB read, results below:", "green"))
            print(' = '.join([x.prettyPrint() for x in varBind]))



# SNMP v3 Read Test
# Paul


# SNMP v3 Write Test
# Paul


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

