######## IMPORTED LIBRARIES ########
### STANDARD LIBRARIES ###
from multiprocessing import Process, Queue
from time import sleep, ctime
import os
import shutil
import ssl
import socket

### LOCAL FILES ###
from secrets_1 import *
from test_configuration import *

### PYPI LIBRARIES ###
from termcolor import colored
import ipaddr

# pyATS
from pyats.topology import loader

# for SNMP tests
from pysnmp.hlapi import *
from pysnmp.carrier.asynsock.dgram import udp, udp6
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv, context, cmdrsp
from pysnmp.proto import rfc1902

# for NTP test
import ntplib

# for HTTP tests
import requests

# for TFTP tests
from tftpy import TftpClient
from tftpy import TftpServer
import paramiko

# for FTP tests
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer

######## FUNCTIONS #######
def ip_version(ip):
    # ip_version takes in ip address and returns 4 or 6 (int)
    # ip - a string which must be an ipv4 or v6 address

    try:
        test_device_ipaddr = ipaddr.IPAddress(ip)
    except:
        # This is not an IPv4 or an IPv6 address
        print(colored("IP address is malformed... Exiting", "red"))
        exit()

    if (test_device_ipaddr.version == 4):
        return 4
    elif (test_device_ipaddr.version == 6):
        return 6
    else:
        # This is not an IPv4 or an IPv6 address
        print(colored("IP address is malformed... Exiting", "red"))
        exit()


def connect_host(device = '', protocol = '', command = ' '):
    # pyATS Connection Function
    # device - hostname of device being tested
    # protocol - connection protocol being tested (telnet or ssh)
    # command - command used to test connection
    testbed = loader.load('pyATS/testbed.yaml')
    try:
        dev = testbed.devices[device]
        dev.connect(via = protocol, log_stdout=False)
    except:
        return Null, Null
    
    if (not command.isspace()):
        dev.configure('file prompt quiet')
        dev.execute(command)

    return dev, testbed


def file_on_flash(device, filename='test.txt'):
    # Checks to see if filename exists on the flash of the given device
    # Returns True or False
    # device - pyats device object
    # filename - name of the file to look for on the flash
    result = device.execute('dir ' + filename)

    if ('No such file' in result):
        return False
    else:
        return True


def del_from_flash(device, filename='test.txt'):
    # Deletes a file from the flash
    # Returns True if file was succeesfully delted, False if not
    # device - pyATS device object
    # filename - Name of the file to delete

    # USE PYATS DELETE FUNCTION INSTEAD
    result = device.execute('del ' + filename + '\n\n\n')
    print(result)
    if ('Error deleting' in result):
        return False
    else:
        return True


def file_on_mav(filename=''):
    # Return True if file exists on mav6 box, False if not
    # filename - name of the file to look for
    if os.path.isfile(filename):
        return True
    else:
        return False


def del_from_mav(filename=''):
    # Delete this file from mav6 box
    # filename - name of file to delete
    os.remove(filename)


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


def ping_client(device = ''):
    # ping_client connects to the test device and tries to ping an
    #   ip address from there.
    device, testbed = connect_host(device, 'ssh')
    print(colored(('Attempting ping client test...'), 'yellow'))
    print(device.ping(LOCAL_DEVICE))

    
def http_test(ip= '', verify = True):
# http_test makes an http get request to the test device
# verify - uses HTTPS if set to false
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


def snmp_start_trap_receiver(q, snmp_version=2, ip=MAV6_IPV4, port=162):
    # snmp_start_trap_receiver will be called as its own process
    #   It starts a MAV6 embedded trap reciever that will
    #   collect SNMP traps from the test device
    #
    # q - a multiprocess communications q that received traps will be pushed onto
    # snmp_version - 2 or 3
    # ip - ip address (v4 or v6) the MAV6 trap receiver will listen on
    # port - The port the MAV6 trap receiver will listen on

    def cbFun(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
        # Call back function, This runs when a trap is received
        print('Received a Trap!')
        for name, val in varBinds:
            print('Receiver: ' + name.prettyPrint() + ' = ' + val.prettyPrint())
            q.put(name.prettyPrint() + ' = ' + val.prettyPrint())

    snmp_engine = engine.SnmpEngine(rfc1902.OctetString(hexValue='80000009030000c1b1129980'))
    if (ip_version(ip) == 4):
        print('Using IPv4 as a Transport on receiver')
        config.addTransport(snmp_engine, udp.domainName, 
                            udp.UdpTransport().openServerMode((ip, port)) )
    else:
        print('Using IPv6 as a Transport on receiver')
        config.addTransport(snmp_engine, udp6.domainName + (1,), 
                            udp6.Udp6Transport().openServerMode((ip, port)) )

    if (snmp_version == 2):
        print('starting snmp trap receiver v2...')
        config.addV1System(snmp_engine, 'my-area', COM_RW)
    elif (snmp_version == 3):
        print('starting snmp trap receiver v3...')
        config.addV3User(snmp_engine, 'mavuser')
        '''
        config.addVacmUser(snmp_engine, 3, '***REMOVED***', 'authPriv', 
                           (1,3,6,1,2,1), (1,3,6,1,2,1) )
        '''

    else:
        print(colored("Only SNMP version 2 or 3 is supported... Exiting", "red"))

    ntfrcv.NotificationReceiver(snmp_engine, cbFun)
    snmp_engine.transportDispatcher.jobStarted(1)

    try:
        print('Starting engine on ' + ip + ':' + str(port))
        snmp_engine.transportDispatcher.runDispatcher()
    except:
        snmp_engine.transportDispatcher.closeDispatcher()
        raise


def snmp_trap_send(destination=MAV6_IPV4, port=162, snmp_version = 2):
    # snmp_trap_send is strictly for testing the trap receiver
    #   It may never be used in normal mav6 operation
    #   in Normal operation the routers should send the traps to the reciever
    # destination - The ip of the trap will be sent to
    # port - The port the trap will be sent to
    # snmp_version - 2 or 3
    if (snmp_version == 2):
        iterator = sendNotification (
            SnmpEngine(),
            CommunityData('***REMOVED***', mpModel=0), #for version 2c
            #UsmUserData('***REMOVED***', authKey='***REMOVED***', privKey='***REMOVED***', 
            #            authProtocol=usmHMACSHAAuthProtocol, privProtocol=usmAesCfb128Protocol),
            UdpTransportTarget((destination, port)) if ip_version(destination) == 4 else Udp6TransportTarget((destination, port)),
            #UdpTransportTarget((destination, port)),
            # Udp6TransportTarget((destination, port)),  # for IPv6 transport
            ContextData(),
            'trap',
            NotificationType(
                ObjectIdentity('1.3.6.1.6.3.1.1.5.2')
            ).addVarBinds(
                ('1.3.6.1.6.3.1.1.4.3.0', '1.3.6.1.4.1.20408.4.1.1.2'),
                ('1.3.6.1.2.1.1.1.0', OctetString('my system'))
            ).loadMibs(
                'SNMPv2-MIB'
            )
        )
    elif(snmp_version == 3):
        # send notification for v3
        iterator = sendNotification (
            SnmpEngine(rfc1902.OctetString(hexValue='80000009030000c1b1129980')),
            UsmUserData('mavuser'),
            UdpTransportTarget((destination, port)) if ip_version(destination) == 4 else Udp6TransportTarget((destination, port)),
            # UdpTransportTarget((destination, port)),
            # Udp6TransportTarget((destination, port)),  # for IPv6 transport
            ContextData(),
            'trap',
            NotificationType(
                ObjectIdentity('1.3.6.1.6.3.1.1.5.2')
            ).addVarBinds(
                ('1.3.6.1.6.3.1.1.4.3.0', '1.3.6.1.4.1.20408.4.1.1.2'),
                ('1.3.6.1.2.1.1.1.0', OctetString('my system'))
            ).loadMibs(
                'SNMPv2-MIB'
            )
        )
    else:
        print('Unknow snmp version!')
        exit()

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if(errorIndication):
        print(errorIndication)


def tftp_server_download( ip, port=69, filename='test.cfg' ):
    # From the test subjects perspective
    # The test device acts as a tftp server 
    # mav6 tries to download a file from the test subject tftp server.
    #
    # ip - ip address of the test device where tftp-server runs
    # port - udp port of the tftp server
    # filename - the file name to download from the test device
    if ( ip_version(ip) == 4 ):
        print(colored("Attempting TFTP download via IPv4", "yellow"))        
        client = TftpClient(ip, port)
    else:
        print(colored("Attempting TFTP download via IPv6", "yellow"))
        client = TftpClient(ip, port, af_family=socket.AF_INET6 )

    try:
        # CHECK HERE TO SEE IF FILE IS ALREADY LOCAL
        if file_on_mav(filename):
            print("tftp test download file exists locally... deleting")
            del_from_mav(filename)
            sleep(1)
        else:
            print("tftp test download file does not exist locally... continuing")
        client.download(filename, filename)
        # CHECK HERE TO SEE IF FILE IS LOCAL
        if file_on_mav(filename):
            print(colored("TFTP Download success!!!", "green"))
        else:
            print(colored("TFTP Download failed", "red"))
    except:
        print(colored("TFTP Download failed", "red"))


def start_server(transfer_protocol='tftp', ip=MAV6_IPV4):
    # start_server will be called as a new process
    # It will start an embedded tftp, ftp or http(s) server
    # for the test device to act as a client against
    #
    # transerfer_protol = tftp, ftp or http
    # ip = The IP address the embedded server will listen on
    #
    if (transfer_protocol == 'tftp'):
        print('starting tftp server...')
        server = TftpServer('.')
        if (ip_version(ip) == 6):
            server.listen(ip, 69, af_family=socket.AF_INET6)
        else:
            server.listen(ip, 69)
    elif (transfer_protocol == 'ftp'):
        print('starting ftp server...')
        authorizer = DummyAuthorizer()
        authorizer.add_user('paul', 'elephant060', '.')
        handler = FTPHandler
        handler.authorizer = authorizer
        server = FTPServer((ip,21), handler)
        server.serve_forever()
    elif (transfer_protocol == 'sftp'):
        print('No embedded server for ' + transfer_protocol)
    elif (transfer_protocol == 'http'):
        print('Starting http server...')
        if (ip_version(ip) == 6):
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

    elif (transfer_protocol == 'https'):        
        print('Starting https server...')
        if (ip_version(ip) == 6):
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
            response = "HTTP/1.0 200 OK\n\n Mav6 File Transfer completed successfully!"
            client_connection.sendall(response.encode())
            client_connection.close()
    else:
        print('No embedded server for ' + transfer_protocol)


def filetransfer_client_download(device_hostname='', device_protocol='ssh',
                                 server_ip='', transfer_protocol='tftp'):
    # From the test subjects perspective
    # The test device acts as a tftp, ftp or http(s) client 
    # The test subject tries to download a file from mav6 embedded server.
    #
    # device_hostname - use this to connect to the device with connect_host function (pyats)
    # device_protocol - the protocol used to connect to the test device ssh or telnet
    # server_ip - the ip address of the embedded mav6 server (tftp, ftp, http, etc)
    # transfer_protocol - file transfer protocol to test, tftp (ftp, scp, http, etc)

    # First connect to the test device
    if ( ip_version(server_ip) == 6 ):
        server_ip = '[' + server_ip + ']'

    if (transfer_protocol == 'tftp'):
        command = 'copy tftp://' + server_ip + '/test.txt flash:/\n\n\n' 
        connect_host(device=device_hostname, protocol='ssh', command=command)
        sleep(5)
    elif (transfer_protocol == 'ftp'):
        command = 'copy ftp://paul:elephant060@' + server_ip + '/test.txt flash:/\n\n\n' 
        connect_host(device=device_hostname, protocol='ssh', command=command)
        sleep(5)
    elif (transfer_protocol == 'http'):
        command = 'copy http://' + server_ip + '/test.txt flash:/\n\n\n' 
        connect_host(device=device_hostname, protocol='ssh', command=command)
        sleep(5)
    elif (transfer_protocol == 'https'):
        command = 'copy https://' + server_ip + '/test.txt flash:/\n\n\n' 
        connect_host(device=device_hostname, protocol='ssh', command=command)
        sleep(5)
    else:
        print("File transfer protocol not supported.")
        exit()

 
def ca_buildca(server_ip=''):
    # Delete old CA
    if (os.path.isdir('mav6-certs')):
        shutil.rmtree('mav6-certs')

    # Create the rootCA.key and rootCA.crt
    os.mkdir('mav6-certs')
    os.chdir('mav6-certs')
    command = 'openssl req -x509 -sha256 -days 3650 -nodes  -newkey rsa:4096 -subj ' + \
                '"/CN=mav6b.ciscofederal.com/C=US/L=Richfield/ST=Ohio"  -keyout rootCA.key -out rootCA.crt'
    os.system(command)

    #Build the server CSR
    os.system('openssl genrsa -out server.key 4096')
    with open('server_csr.conf', 'w+') as f:
        f.writelines(SERVER_CSR_CONF)
    sleep(2)
    os.system('openssl req -new -key server.key -out server.csr -config server_csr.conf')
    # Create the server certificate
    with open('server_cert.conf', 'w+') as f:
        f.writelines(SERVER_CERT_CONF)

    sleep(2)
    command = 'openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key ' + \
                '-CAcreateserial -out server.crt -days 3650 -sha256 ' + \
                '-extfile server_cert.conf'
    os.system(command)

    #get fingerprint of rootCA.crt
    command = 'openssl z509 in rootCA.crt -noout -fingerprint >> fingerprint.txt'
    os.system(command)

def rtr_add_trustpoint(device='', fingerprint=''):
    with open('fingerprint.txt') as fileptr:
        fingerprint = fileptr.read()
    print('fingerprint is: \n')
    print(fingerprint)
    equal_position = fingerprint.rfind('=')
    fingerprint=fingerprint[equal_position:]
    print(fingerprint)
    fingerprint = fingerprint.replace(':', '')
    print(fingerprint)

    device.configure ('crypto pki trustpoint MAV6-TP\n' + \
                        'enrollment terminal\n' + \
                        'revocation-check none \n' + \
                        'fingerprint  ' + fingerprint + '\n'
                        )


######## MAIN PROGRAM ########

# Note: ALL comments are made from the perspective of the test device
# I.E. Telnet server test means the Test device is acting as the TFTP Server

os.chdir('mav6-certs')
#get fingerprint of rootCA.crt
command = 'openssl z509 in rootCA.crt -noout -fingerprint >> fingerprint.txt'
os.system(command)


### SERVER TESTS ###
#ca_buildca('10.112.1.106')

# Ping Server Test
if PING_SERVER:
    result = ping_host(TEST_DEVICE)
    if (result):
        print(colored("Ping Server Test Success", "green"))
    else:
        print(colored("Ping Server Test Failed", "red"))


# Telnet Server Test
if TELNET_SERVER:
    device = connect_host(TEST_DEVICE_HOSTNAME, 'telnet')
    if (device == Null):
        print(colored("Telnet Server Test Failed", "red"))
    else:
        print(colored("Telnet Server Test Success", "green"))


# SSH Server Test
if SSH_SERVER:
    device = connect_host('mgmt', 'ssh')
    if (device == Null):
        print(colored("SSH Server Test Failed", "red"))
    else:
        print(colored("SSH Server Test Success", "green"))


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
    # Connect to test device and check for test file on flash
    device, testbed = connect_host( device=TEST_DEVICE_HOSTNAME, protocol='ssh')
    if(file_on_flash(device, filename='test.txt')):
        del_from_flash(device, 'test.txt')
    if (ip_version(TEST_DEVICE) == 4):
        tftp_server_process = Process(target=start_server, name='tftpserver', 
                                      args=('tftp', MAV6_IPV4,))
    else:
        tftp_server_process = Process(target=start_server, name='tftpserver', 
                                      args=('tftp', MAV6_IPV6,))


    print('starting tftp server process')
    tftp_server_process.start()
    sleep(5)

    if (ip_version(TEST_DEVICE) == 4):
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME, device_protocol='ssh',
                                 server_ip=MAV6_IPV4, transfer_protocol='tftp')
    else:
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME, device_protocol='ssh',
                                 server_ip=MAV6_IPV6, transfer_protocol='tftp')


    # Check to see if file transfer was successful and print message
    if (file_on_flash(device, filename='test.txt')):
        print(colored("TFTP Client Test Successful", "green"))
    else:
        print(colored("TFTP Client Test Failed", "red"))
    
    sleep(2)
    tftp_server_process.kill()

# FTP Client test
if FTP_CLIENT:
    # Connect to test device and check for test file on flash
    device, testbed = connect_host( device=TEST_DEVICE_HOSTNAME, protocol='ssh')
    if(file_on_flash(device, filename='test.txt')):
        del_from_flash(device, 'test.txt')

    if (ip_version(TEST_DEVICE) == 4):
        ftp_server_process = Process(target=start_server, name='ftpserver', 
                                     args=('ftp',MAV6_IPV4,))
    else:
        ftp_server_process = Process(target=start_server, name='ftpserver', 
                                     args=('ftp',MAV6_IPV6,))
        
    print('starting ftp server process')
    ftp_server_process.start()
    sleep(5)

    if (ip_version(TEST_DEVICE) == 4):
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME, device_protocol='ssh',
                                    server_ip=MAV6_IPV4, transfer_protocol='ftp')
    else:
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME, device_protocol='ssh',
                                    server_ip=MAV6_IPV6, transfer_protocol='ftp')


    # Check to see if file transfer was successful and print message
    if (file_on_flash(device, filename='test.txt')):
        print(colored("FTP Client Test Successful", "green"))
    else:
        print(colored("FTP Client Test Failed", "red"))
    
    sleep(2)
    ftp_server_process.kill()

# HTTP client Test
if HTTP_CLIENT:
    # Connect to test device and check for test file on flash
    device, testbed = connect_host( device=TEST_DEVICE_HOSTNAME, protocol='ssh')
    if(file_on_flash(device, filename='test.txt')):
        del_from_flash(device, 'test.txt')

    print('starting http server process')
    if (ip_version(TEST_DEVICE) == 4):
        http_server_process = Process(target=start_server, name='httpserver', 
                                      args=('http', MAV6_IPV4,))
        http_server_process.start()
        sleep(5)
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME, device_protocol='ssh', 
                                     server_ip=MAV6_IPV4, transfer_protocol='http')
    else:
        http_server_process = Process(target=start_server, name='httpserver', 
                                      args=('http',MAV6_IPV6,))
        http_server_process.start()
        sleep(5)
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME,  device_protocol='ssh',
                                     server_ip=MAV6_IPV6, transfer_protocol='http')
    # Check to see if file transfer was successful and print message
    if (file_on_flash(device, filename='test.txt')):
        print(colored("HTTP Client Test Successful", "green"))
    else:
        print(colored("HTTP Client Test Failed", "red"))
    
    sleep(2)
    http_server_process.kill()


# HTTPS client Test
if HTTPS_CLIENT:
    # Connect to test device and check for test file on flash
    device, testbed = connect_host( device=TEST_DEVICE_HOSTNAME, protocol='ssh')
    if(file_on_flash(device, filename='test.txt')):
        del_from_flash(device, 'test.txt')
    
    # USE OS COMMANDS TO CREATE DIR, OPENSSL ROOTCA.KEY ROOTCA.CRT, SERVER.KEY, SERVER.CSR
    # SERVER.CRT, 
    print('starting https server process')
    if (ip_version(TEST_DEVICE) == 4):
        https_server_process = Process(target=start_server, name='httpsserver', 
                                       args=('https',MAV6_IPV4,))
        https_server_process.start()
        sleep(5)
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME,  device_protocol='ssh',
                                     server_ip=MAV6_IPV4, transfer_protocol='https')
    else:
        https_server_process = Process(target=start_server, name='httpsserver', 
                                       args=('https',MAV6_IPV6,))
        https_server_process.start()
        sleep(5)
        filetransfer_client_download(device_hostname=TEST_DEVICE_HOSTNAME,  device_protocol='ssh',
                                     server_ip=MAV6_IPV6, transfer_protocol='https')

    # USE PYATS TO CREATE THE KEYS, TP, AUTHENTICATE THE ROOTCA.CRT, CREATE ROUTER CSR
    # USE OS COMMANES TO SIGN THE CSR
    # USE PYATS TO INSTALL THE ROUTER CERT

    # Check to see if file transfer was successful and print message
    if (file_on_flash(device, filename='test.txt')):
        print(colored("HTTPS Client Test Successful", "green"))
    else:
        print(colored("HTTPS Client Test Failed", "red"))
    
    sleep(2)
    https_server_process.kill()


# SNMP v2 Trap Test
if SNMPV2_TRAP:
    if (ip_version(TEST_DEVICE) == 4):
        mav6_ip = MAV6_IPV4
    else:
        mav6_ip = MAV6_IPV6

    q = Queue()
    snmp_trap_receiver_process = Process(target=snmp_start_trap_receiver, name='snmptrapreceiver', 
                                         args=(q,2, mav6_ip,162,))

    print('starting snmpv2 trap receiver process')
    snmp_trap_receiver_process.start()
    sleep(5)
    # Below sends a test trap from mav6 to mav6 trap receiver, leave commented unless testing
    #snmp_trap_send(destination=mav6_ip, port=162, snmp_version=2)
    
    # Configure TEST_DEVICE to send SNMP traps to trap receiver
    device, testbed = connect_host(TEST_DEVICE_HOSTNAME, 'ssh')
    device.configure ('snmp-server host ' + mav6_ip + ' traps version 2c ' + COM_RW + \
                      ' udp-port 162 config\n' )

    sleep(5)    

    # Check the queue created by the SNMP receiver for a trap sent by TEST_DEVICE
    received_snmp = False
    while(not q.empty()):
        message = q.get()
        if('my system' in message):
            print('SNMPv3 message arrived at receiver from snmp_trap_send') 
        elif('***REMOVED***' in message):
            print('SNMPv3 message arrived at receiver from TEST_DEVICE')
            received_snmp = True
        else:
            # Unknown SNMP sender
            pass 

    # Print Test results to screen
    if (received_snmp):
        print(colored("SNMPv3 Trap Test Successful", "green"))
    else:
        print(colored("SNMPv3 Trap Test Failed", "red"))


    sleep(2)
    snmp_trap_receiver_process.kill()

# SNMP v3 Trap Test
if SNMPV3_TRAP:
    if (ip_version(TEST_DEVICE) == 4):
        mav6_ip = MAV6_IPV4
    else:
        mav6_ip = MAV6_IPV6

    q = Queue()
    snmp_trap_receiver_process = Process(target=snmp_start_trap_receiver, name='snmptrapreceiver', 
                                        args=(q,3, mav6_ip,162,))

    print('starting snmpv3 trap receiver process')
    snmp_trap_receiver_process.start()
    sleep(5)
    # Below sends a test trap from mav6 to mav6 trap receiver, leave commented unless testing
    snmp_trap_send(destination=mav6_ip, port=162, snmp_version=3)

    # Configure TEST_DEVICE to send SNMP traps to trap receiver
    device, testbed = connect_host(TEST_DEVICE_HOSTNAME, 'ssh')
    device.configure ('snmp-server group mav6group v3 noauth\n' + \
                        'snmp-server user mav6user mav6group v3\n' + \
                        'snmp-server enable traps\n' + \
                        'snmp-server host ' + mav6_ip + ' traps version 3 noauth mav6user\n'
                        )
    sleep(5) 

    # Check the queue created by the SNMP receiver for a trap sent by TEST_DEVICE
    received_snmp = False
    while(not q.empty()):
        message = q.get()
        if('my system' in message):
            print('SNMPv3 message arrived at receiver from snmp_trap_send') 
        elif('***REMOVED***' in message):
            print('SNMPv3 message arrived at receiver from TEST_DEVICE')
            received_snmp = True
        else:
            # Unknown SNMP sender
            pass 

    # Print Test results to screen
    if (received_snmp):
        print(colored("SNMPv3 Trap Test Successful", "green"))
    else:
        print(colored("SNMPv3 Trap Test Failed", "red"))

    
    sleep(2)
    snmp_trap_receiver_process.kill()

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
