######## IMPORTED LIBRARIES ########
import os
from termcolor import colored

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


# SCP Server Test
# Jay


# TFTP Server Test


# HTTP Server Test


# HTTPS Server Test


# SNMP v2 Read Test
# Paul


# SNMP v2 Write Test
# Paul


# SNMP v3 Read Test
# Paul


# SNMP v3 Write Test
# Paul


# NTP v4 Server Test


# DHCP Server Test



### CLIENT TESTS ###

# Ping Client Test
ping_host(TEST_DEVICE)
print(colored("Testing termcolor", "red"))


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

