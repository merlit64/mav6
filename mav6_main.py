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


# Ping Server Test
ping_host(TEST_DEVICE)
print(colored("Testing termcolor", "red"))


# Telnet Server Test


# SSH Server Test


# SCP Server Test