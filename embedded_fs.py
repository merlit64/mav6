import socket
import ssl

from mav6utils import *
from tftpy import TftpServer

# for FTP tests
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from pyftpdlib.authorizers import DummyAuthorizer


def start_server(transfer_protocol='tftp', ip=''):
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
    elif (transfer_protocol == 'syslog'):
        print('starting syslog server...')
        if (ip_version(ip) == 6):
            server_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((ip, 514))
        while True:
            message, address = server_socket.recvfrom(1024)
            print('Received syslog from ' + address )
            print(message)
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
        context = ssl.SSLContext()
        context.verify_mode = ssl.CERT_NONE
        context.load_verify_locations('keys_and_certs/rootCA.crt')
        context.load_cert_chain(certfile='keys_and_certs/server.crt', 
                                keyfile='keys_and_certs/server.key')

        if (ip_version(ip) == 6):
            server_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
        wrapped_socket = context.wrap_socket(server_socket, server_side=True)
        wrapped_socket.bind((ip, 443))
        wrapped_socket.listen(1)
        while True:
            try:
                client_connection, client_address = wrapped_socket.accept()
                request = client_connection.recv(1024).decode()
                print(request)
                response = "HTTP/1.0 200 OK\n\n Mav6 File Transfer completed successfully!"
                client_connection.sendall(response.encode())
                client_connection.close()
            except:
                # An unknown cert by the browser trips an error and will end the server process
                # this pass lets the loop continue, and thefore the https server continue
                # despite the self-signed or unknown cert error
                pass
    else:
        print('No embedded server for ' + transfer_protocol)

def snmp_start_trap_receiver(q, snmp_version=2, ip='', port=162, community=''):
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
        config.addV1System(snmp_engine, 'my-area', community)
    elif (snmp_version == 3):
        print('starting snmp trap receiver v3...')
        config.addV3User(snmp_engine, 'mavuser')
        '''
        config.addVacmUser(snmp_engine, 3, 'v3user', 'authPriv', 
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



def start_notification_server(transfer_protocol='syslog', ip=''):
    # start_syslog_server will be called as a new process
    # It will start an embedded syslog server
    # for the test device to act as a client against
    #
    # transerfer_protol = syslog
    # ip = The IP address the embedded server will listen on
    #

    print('starting ' + transfer_protocol + ' server...')
    if (transfer_protocol == 'syslog'):
        if (ip_version(ip) == 6):
            server_socket = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        else:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((ip, 514))
    else:
        print('No embedded server for ' + transfer_protocol)
        return False
    while True:
        message = server_socket.recvfrom(1024)
        print('Received ' + transfer_protocol + ' message:')
        print(message)
