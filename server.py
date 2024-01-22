from time import ctime
from mav6utils import *
from termcolor import colored
import requests
import socket
from time import sleep

# for SNMP tests
from pysnmp.hlapi import *
from pysnmp.carrier.asynsock.dgram import udp, udp6
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv, context, cmdrsp
from pysnmp.proto import rfc1902

from tftpy import TftpClient

# for NTP test
import ntplib


def ping_host(ip):
    # ping_host uses os commands to ping an ip address then returns True/False
    # ip - ip address to ping, v4 or v6
    if ( ip_version(ip) == 4 ):
        response = os.system("ping -c 1 " + ip)
    else:
        response = os.system("ping6 -c 1 " + ip)
    if (response == 0):
        print("Reachability Check passed...")
        return True
    else:
        return False

def http_test(ip= '', verify = True):
    # HTTP Test Function
    # http_test makes an http get request to the test device
    # verify - uses HTTPS if set to false
    try:
        ip2 = ipaddr.IPAddress(ip)
        print("IP address is good.  Version is IPv%s.  Building URL..." % ip2.version)
    except:
        # This is not an IPv4 or an IPv6 address
        print("IP address is malformed... Exiting")
        exit()
    
    if verify:
        http_string, http_print = "http://", "HTTP"
    else:
        http_string, http_print = "https://", "HTTPS"
    
    if ip2.version == 6:
        url = http_string + "[{0}]".format(ip2.compressed)  
    else:
        url = http_string + ip2.compressed
        
    try:
        r = requests.get(url, verify = verify)
        code = r.status_code
    except:
        code = 0
    
    return str(code)
    
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
    
    # Build SNMP get or set command
    if (action == "read" and version == "v2"):
        iterator = getCmd(SnmpEngine(),
                        CommunityData(community),
                        UdpTransportTarget((ip, port)) if ip_version(ip) == 4 else Udp6TransportTarget((ip, port)),
                        ContextData(),
                        ObjectType(ObjectIdentity(module, parent, suffix)))

    elif ( action == "write" and version == "v2" ):
        iterator = setCmd(SnmpEngine(),
                        CommunityData(community),
                        UdpTransportTarget((ip, port)) if ip_version(ip) == 4 else Udp6TransportTarget((ip, port)),
                        ContextData(),
                        ObjectType(ObjectIdentity(module, parent, suffix), mib_value))

    elif ( action == "read" and version == "v3" ):
        iterator = getCmd(SnmpEngine(),
           UsmUserData(userName=userName, authKey=authKey, privKey=privKey, 
                       authProtocol=authProtocol, privProtocol=privProtocol),
           UdpTransportTarget((ip, port)) if ip_version(ip) == 4 else Udp6TransportTarget((ip, port)),
           ContextData(),
           ObjectType(ObjectIdentity(module, parent, suffix)))

    elif ( action == "write" and version == "v3" ):
        iterator = setCmd(SnmpEngine(),
            UsmUserData(userName=userName, authKey=authKey, privKey=privKey, 
                       authProtocol=authProtocol, privProtocol=privProtocol),
            UdpTransportTarget((ip, port)) if ip_version(ip) == 4 else Udp6TransportTarget((ip, port)),
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
        return False
    else:
        if errorStatus:  # SNMP agent errors
            #print(colored("SNMP" + version + " " + action + " Failed.  Error message:", "red"))
            #print('%s at %s' % (errorStatus.prettyPrint(), varBinds[int(errorIndex)-1] if errorIndex else '?'))
            return False
        else:
            for varBind in varBinds:  # SNMP response contents
                #print(colored("SNMP" + version + " " + action + " Succeeded!.  Results are below:", "green"))
                #print(' = '.join([x.prettyPrint() for x in varBind]))
                return True


def tftpscp_server_download( ip, port=69, filename='test.cfg', username='', password='' ):
    # From the test subjects perspective
    # The test device acts as a tftp server 
    # mav6 tries to download a file from the test subject tftp server.
    #
    # ip - ip address of the test device where tftp-server runs
    # port - udp port of the tftp server, if 443 then use scp
    # filename - the file name to download from the test device

    try:
        # CHECK HERE TO SEE IF FILE IS ALREADY LOCAL
        if file_on_mav(filename):
            print("tftp test download file exists locally... deleting")
            del_from_mav(filename)
            sleep(1)
        else:
            print("tftp test download file does not exist locally... continuing")
    except:
        print(colored("TFTP Download failed", "red"))

    if ( port == 443): # SCP over v4 or v6
        print('attempting scp download from test device at ' + ip)
        command = 'sshpass -p "' + password + '" scp ' + username + \
            '@[' + ip + ']:flash:/from_testdevice.txt from_testdevice.txt'
        os.system(command)
    elif ( ip_version(ip) == 4 and port != 443): # TFP over v4
        client = TftpClient(ip, port)
        print('attempting tftp download from test device at ' + ip)
        client.download(filename, filename)
    elif (ip_version(ip) == 6 and port != 443):
        client = TftpClient(ip, port, af_family=socket.AF_INET6 )
        print('attempting tftp download from test device at ' + ip)
        client.download(filename, filename)
    else:
        return False

    # CHECK HERE TO SEE IF FILE IS LOCAL
    if file_on_mav(filename):
        return True
    else:
        return False

def ntp_call(ip=''):
    c = ntplib.NTPClient()
    try:
        response = c.request(ip, version = 4)
    except:
        return False
        
    print("NTP TIME IS " + ctime(response.tx_time) + " FROM NTP SERVER " + ip)
    return True
