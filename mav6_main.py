######## IMPORTED LIBRARIES ########
from multiprocessing import Process, current_process
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
import socketserver

# for NTP test
import ntplib
from time import ctime

# for file transfer tests
from genie.libs.filetransferutils import FileServer

# for HTTP tests
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler, SimpleHTTPRequestHandler
import ssl

# for TFTP tests
from tftpy import TftpClient
from tftpy import TftpServer
import paramiko

# for FTP tests
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

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


def ping_client(device = ''):
    device, testbed = connect_host(device, 'ssh')
    print(colored(('Attempting ping client test...'), 'yellow'))
    print(device.ping(LOCAL_DEVICE))

    
# pyATS Connection Function
# device - hostname of device being tested
# protocol - connection protocol being tested (telnet or ssh)
# command - command used to test connection
def connect_host(device = '', protocol = '', command = ' '):
    testbed = loader.load('pyATS/testbed.yaml')

    test = testbed.devices[device]

    test.connect(via = protocol, log_stdout=False)

    if (not command.isspace):
        device.execute(command)

    return test, testbed
    
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

def tftp_server_download( ip, port=69, filename='test.cfg' ):
    # From the test subjects perspective
    # The test device acts as a tftp server 
    # mav6 tries to download a file from the test subject tftp server.
    #
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


def start_server(transfer_protocol='tftp', ip=MAV6_IPV4):

    try:
        ip2 = ipaddr.IPAddress(ip)
        
    except:
        # This is not an IPv4 or an IPv6 address
        print(colored("IP address is malformed... Exiting", "red"))
        exit()

    if (transfer_protocol == 'tftp'):
        print('starting tftp server...')
        server = TftpServer('.')
        server.listen('0.0.0.0', 69)
    elif (transfer_protocol == 'ftp'):
        print('starting ftp server...')
        authorizer = DummyAuthorizer()
        authorizer.add_user('paul', 'elephant060', '.')
        handler = FTPHandler
        handler.authorizer = authorizer
        server = FTPServer(('',21), handler)
        server.serve_forever()
    elif (transfer_protocol == 'sftp'):
        print('No embedded server for ' + transfer_protocol)
    elif (transfer_protocol == 'http'):
        print('Starting http server...')
        if (ip2.version == 6):
            server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        server_socket.bind((ip, 80))
        server_socket.listen(1)
        while True:
            client_connection, client_address = server_socket.accept()
            request = client_connection.recv(1024).decode()
            print(request)
            response = "HTTP/1.0 200 OK\n\n Hello World"
            client_connection.sendall(response.encode())
            client_connection.close()



        ##handler = SimpleHTTPRequestHandler
        ##server = socketserver.TCPServer(('2005:1117:1:1:fc74:d46b:062c:59e1', 80), handler)
        #server = BaseHTTPServer(('10.112.1.106', 80), BaseHTTPRequestHandler)
        ##server.serve_forever()
    elif (transfer_protocol == 'https'):        
        print('Starting https server...')
        if (ip2.version == 6):
            server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        wrapped_socket = ssl.wrap_socket(server_socket, certfile='keys-certs/server.crt', 
                                         keyfile='keys-certs/server.key', server_side=True)
        wrapped_socket.bind((ip, 443))
        wrapped_socket.listen(1)
        while True:
            client_connection, client_address = wrapped_socket.accept()
            request = client_connection.recv(1024).decode()
            print(request)
            response = "HTTP/1.0 200 OK\n\n Hello World"
            client_connection.sendall(response.encode())
            client_connection.close()

        '''
        handler = SimpleHTTPRequestHandler
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        
        context.load_cert_chain('../cert.pem')
        server_address = ('10.112.1.106', 443)

        server = socketserver.TCPServer(server_address, handler)
        server.socket = context.wrap_socket(server.socket, server_side=True)

        server.serve_forever()
        '''
    else:
        print('No embedded server for ' + transfer_protocol)


def filetransfer_client_download(ip='', device_protocol='ssh', transfer_protocol='tftp'):
    # From the test subjects perspective
    # The test device acts as a tftp client 
    # mav6 acts as the tftp server
    # The test subject tries to download a file from mav6 tftp server.
    #
    # ip - the name of the test device in the testbed yaml file
    # device_protocol - the protocol used to connect to the test device ssh or telnet
    # transfer_protocol - file transfer protocol to test, tftp (ftp, scp, http are futures)

    # First connect to the test device
    conn = paramiko.SSHClient()
    conn.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    conn.connect(TEST_DEVICE, username=CLI_USER, password= USER_PASS)
    router_conn = conn.invoke_shell()
    print("Connected to Router\n")

    try:
        ip2 = ipaddr.IPAddress(ip)
        
    except:
        # This is not an IPv4 or an IPv6 address
        print(colored("IP address is malformed... Exiting", "red"))
        exit()
    if ( ip2.version == 6 ):
        ip = '[' + ip + ']'

    if (transfer_protocol == 'tftp'):
        # NEED TO GET TO THE ENABLE PROMPT FIRST
        # NEED ERROR CHECKING
        command = 'copy tftp://' + ip + '/test.txt flash:/\n\n\n' 
        router_conn.send(command)
        sleep(5)
        print(router_conn.recv(5000).decode('utf-8'))
    elif (transfer_protocol == 'ftp'):
        # NEED TO GET TO THE ENABLE PROMPT FIRST
        # NEED ERROR CHECKING
        command = 'copy ftp://paul:elephant060@' + ip + '/test.txt flash:/\n\n\n' 
        router_conn.send(command)
        sleep(5)
        print(router_conn.recv(5000).decode('utf-8'))
    elif (transfer_protocol == 'http'):
        command = 'copy http://' + ip + '/test.txt flash:/\n\n\n' 
        
        router_conn.send(command)
        sleep(5)
        print(router_conn.recv(5000).decode('utf-8'))
    elif (transfer_protocol == 'https'):
        command = 'copy https://' + ip + '/test.txt flash:/\n\n\n' 
        router_conn.send(command)
        sleep(5)
        print(router_conn.recv(5000).decode('utf-8'))
    else:
        print("File transfer protocol not supported.")
        exit()

    # CONFIRM FILE ARRIVED AND RETURN RESULTS

 
######## MAIN PROGRAM ########

# Note: ALL comments are made from the perspective of the test device
# I.E. Telnet server test means the Test device is acting as the TFTP Server


### SERVER TESTS ###

print("Executing Server Tests (where test box acts as the server):\n\n")
try:
    test_device_version = ipaddr.IPAddress(TEST_DEVICE).version
    
except:
    # This is not an IPv4 or an IPv6 address
    print(colored("IP address of TEST_DEVICE is malformed... Exiting", "red"))
    exit()


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
# Linux Server
# Python Script
# IOSXE Device
# pyATS https://developer.cisco.com/docs/genie-docs/
if PING_CLIENT:
    ping_client('mgmt')




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
if TFTP_CLIENT:
    tftp_server_process = Process(target=start_server, name='tftpserver', args=('tftp',))

    print('starting tftp server process')
    tftp_server_process.start()
    sleep(5)
    filetransfer_client_download(ip='10.112.1.106', device_protocol='ssh', transfer_protocol='tftp')

    sleep(2)
    tftp_server_process.kill()

# FTP Client test
if FTP_CLIENT:
    ftp_server_process = Process(target=start_server, name='ftpserver', args=('ftp',))
    #ftp_client_process = Process(target=filetransfer_client_download, name='filetransfer_client')
    print('starting ftp server process')
    ftp_server_process.start()
    sleep(5)

    filetransfer_client_download(ip='10.112.1.106', device_protocol='ssh', transfer_protocol='ftp')
    sleep(2)
    ftp_server_process.kill()

# HTTP client Test
print('starting http server process')
if HTTP_CLIENT:
    if (test_device_version == 4):
        http_server_process = Process(target=start_server, name='httpserver', 
                                      args=('http', MAV6_IPV4,))
        http_server_process.start()
        sleep(5)
        filetransfer_client_download(ip=MAV6_IPV4, device_protocol='ssh', 
                                     transfer_protocol='http')
    else:
        http_server_process = Process(target=start_server, name='httpserver', 
                                      args=('http',MAV6_IPV6,))
        http_server_process.start()
        sleep(5)
        filetransfer_client_download(ip=MAV6_IPV6, device_protocol='ssh', 
                                     transfer_protocol='http')

    sleep(2)
    http_server_process.kill()


# HTTPS client Test
if HTTPS_CLIENT:
    # USE OS COMMANDS TO CREATE DIR, OPENSSL ROOTCA.KEY ROOTCA.CRT, SERVER.KEY, SERVER.CSR
    # SERVER.CRT, 
    print('starting https server process')
    if (test_device_version == 4):
        https_server_process = Process(target=start_server, name='httpsserver', 
                                       args=('https',MAV6_IPV4,))
        https_server_process.start()
        sleep(5)
        filetransfer_client_download(ip=MAV6_IPV4, device_protocol='ssh', 
                                     transfer_protocol='https')
    else:
        https_server_process = Process(target=start_server, name='httpsserver', 
                                       args=('https',MAV6_IPV6,))
        https_server_process.start()
        sleep(5)
        filetransfer_client_download(ip=MAV6_IPV6, device_protocol='ssh', 
                                     transfer_protocol='https')

    # USE PYATS TO CREATE THE KEYS, TP, AUTHENTICATE THE ROOTCA.CRT, CREATE ROUTER CSR
    # USE OS COMMANES TO SIGN THE CSR
    # USE PYATS TO INSTALL THE ROUTER CERT
    sleep(2)
    https_server_process.kill()


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
