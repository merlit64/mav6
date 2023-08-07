######## IMPORTED LIBRARIES ########
import os


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

# Telnet Server Test


# SSH Server Test


# SCP Server Test