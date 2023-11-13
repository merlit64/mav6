from tftpy import TftpServer
from time import sleep
import socket

srv1 = TftpServer('.')
srv1.listen(listenip='10.112.1.106', listenport=69, af_family=socket.AF_INET)
sleep(150)