import socket
import ssl

from termcolor import colored

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
        wrapped_socket.bind((ip, 14443))
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


