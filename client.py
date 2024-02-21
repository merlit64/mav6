from mav6utils import *
from time import sleep
from termcolor import colored
from multiprocessing import Process, Queue

# pyATS
from pyats.topology import loader
from pyats.utils.fileutils import FileUtils
from genie.libs.sdk.apis.iosxe.ntp.configure import *
from unicon.eal.dialogs import Dialog, Statement

# for SNMP tests
#from pysnmp.hlapi import *
#from pysnmp.carrier.asynsock.dgram import udp, udp6
#from pysnmp.entity import engine, config
#from pysnmp.entity.rfc3413 import ntfrcv, context, cmdrsp
from pysnmp.proto import rfc1902


# Embedded file server function import
from embedded_fs import *
from ca import *


def ping_client(device = '', device_to_ping=''):
    # ping_client connects to the test device and tries to ping an
    #   ip address from there.
    ping_result = device.ping(device_to_ping)
    print(ping_result)
    if ('!!!!' in ping_result ):
        return True
    else:
        return False

def perform_ssh(device, ip_address, username, password):
    
    ssh_dict = {
                'pass_timeout_expire_flag': False,
                'ssh_pass_case_flag': False,
                'enable_pass_flag': False
                }

    def pass_timeout_expire():
        ssh_dict['pass_timeout_expire_flag'] = True

    def send_pass(spawn):
        spawn.sendline(password)

    def ssh_pass_case(spawn):
        ssh_dict['ssh_pass_case_flag'] = True
        # command to exit from the active ssh session from the device prompt itself.
        cli_command = 'exit'
        spawn.sendline(cli_command)


    dialog = Dialog([

            Statement(pattern=r"Password:\s*timeout expired!",
                      action=pass_timeout_expire,
                      loop_continue=False),
            Statement(pattern=r"Password:",
                      action=send_pass,
                      loop_continue=True),
            Statement(pattern=r'Welcome to Ubuntu',
                      action=ssh_pass_case,
                      loop_continue=False),

    ])

    cmd = f'ssh -l {username}'

    cmd += f' {ip_address}'

    try:
        device.execute(cmd, reply=dialog, prompt_recovery=True, timeout=40)

    except Exception as e:
        log.info(f"Error occurred while performing ssh : {e}")

    if ssh_dict['pass_timeout_expire_flag']:
        return False
    if ssh_dict['ssh_pass_case_flag']:
        return True
    
    
def perform_telnet(device, ip_address, username, password):
    
    telnet_dict = {
                'pass_timeout_expire_flag': False,
                'telnet_pass_case_flag': False,
                'enable_pass_flag': False
                }

    def pass_timeout_expire():
        telnet_dict['pass_timeout_expire_flag'] = True

    def send_pass(spawn):
        spawn.sendline(password)
        
    def send_login(spawn):
        spawn.sendline(username)

    def telnet_pass_case(spawn):
        telnet_dict['telnet_pass_case_flag'] = True
        # command to exit from the active ssh session from the device prompt itself.
        cli_command = 'exit'
        spawn.sendline(cli_command)

    dialog = Dialog([

            Statement(pattern=r'Welcome to Ubuntu',
                      action=telnet_pass_case,
                      loop_continue=False),
            Statement(pattern=r"Password:\s*timeout expired!",
                      action=pass_timeout_expire,
                      loop_continue=False),
            Statement(pattern=r"Password:",
                      action=send_pass,
                      loop_continue=True),
            Statement(pattern=r"login:",
                      action=send_login,
                      loop_continue=True),
            
    ])

    cmd = f'telnet {ip_address}'

    try:
        device.execute(cmd, reply=dialog, prompt_recovery=True, timeout=40)

    except Exception as e:
        log.info(f"Error occurred while performing telnet : {e}")

    if telnet_dict['pass_timeout_expire_flag']:
        return False
    if telnet_dict['telnet_pass_case_flag']:
        return True



def telnet_client(device, server_ip, user, secret):
    # telnet client test function
    if (perform_telnet(device, server_ip, user, secret)):
        return True
    else:
        return False


def ssh_client(device, server_ip, user, secret):
    # ssh client test function
    if (perform_ssh(device, server_ip, user, secret)):
        return True
    else:
        return False
        
def ntp_client(device='', ntp_server=''):
    
    ntp_config = [ntp_server]
    print(colored('Attempting NTP server configuration...', 'yellow'))
    configure_ntp_server(device, ntp_config)
    output = device.execute("show run | include ntp")
    if (len(output) == 0):
        return False
    else:
        message = 'NTP server configuration passed: ' + output
        print(colored(message, 'green'))
        return True
    

def snmp_trap_send(destination='', port=162, snmp_version = 2):
    # snmp_trap_send is strictly for testing the trap receiver
    #   It may never be used in normal mav6 operation
    #   in Normal operation the routers should send the traps to the reciever
    # destination - The ip of the trap will be sent to
    # port - The port the trap will be sent to
    # snmp_version - 2 or 3
    if (snmp_version == 2):
        iterator = sendNotification (
            SnmpEngine(),
            CommunityData('FEDcivrw', mpModel=0), #for version 2c
            #UsmUserData('v3user', authKey='C1sco123!', privKey='C1sco123!', 
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

def snmp_trap_client(snmp_version=2, comm_uname='', mav6_ip='', device='' ):

    q = Queue()
    snmp_trap_receiver_process = Process(target=snmp_start_trap_receiver, name='snmptrapreceiver', 
                                         args=(q,2, mav6_ip,162,comm_uname))

    print('starting snmp trap receiver process, version ' + str(snmp_version))
    snmp_trap_receiver_process.start()
    sleep(5)
    # Below sends a test trap from mav6 to mav6 trap receiver, leave commented unless testing
    #snmp_trap_send(destination=mav6_ip, port=162, snmp_version=snmp_version)
    
    # Trigger an event to send a trap
    print('Triggering Test Device to send a trap')
    if snmp_version == 2:
        device.configure ('')
    elif snmp_version == 3:
        device.configure ('')
    else:
        print('That version of SNMP does not exist')
        SystemExit()

    sleep(5)    

    # Check the queue created by the SNMP receiver for a trap sent by TEST_DEVICE
    received_snmp = False
    while(not q.empty()):
        message = q.get()
        if('my system' in message):
            print('SNMP message arrived at receiver from snmp_trap_send test function') 
        elif('netconf' in message):
            print('SNMP message arrived at receiver from TEST_DEVICE')
            received_snmp = True
        else:
            # Unknown SNMP sender
            pass 

    sleep(2)
    snmp_trap_receiver_process.kill()

    return received_snmp



def filetransfer_client_download(device='', server_ip='', transfer_protocol='tftp'):
    # From the test subjects perspective
    # The test device acts as a tftp, ftp or http(s) client 
    # The test subject tries to download a file from mav6 embedded server.
    #
    # device - pyats device
    # server_ip - the ip address of the embedded mav6 server (tftp, ftp, http, etc)
    # transfer_protocol - file transfer protocol to test, tftp (ftp, scp, http, etc)

    # Put brackets around ipv6 address
    if ( ip_version(server_ip) == 6 ):
        server_ip = '[' + server_ip + ']'

    # setup dialog
    def dest_filename_request(spawn):
        spawn.sendline('')
    dialog = Dialog([
        Statement(pattern=r"Destination filename",
                  action=dest_filename_request,
                  loop_continue=True)
    ])
    
    # send copy command
    if (transfer_protocol == 'tftp'):
        cmd = 'copy tftp://' + server_ip + '/test.txt flash:/test.txt' 
        device.execute(cmd, reply=dialog, prompt_recovery=True, timeout=40)
        sleep(5)
    elif (transfer_protocol == 'ftp'):
        cmd = 'copy ftp://paul:elephant060@' + server_ip + '/test.txt flash:/' 
        device.execute(cmd, reply=dialog, prompt_recovery=True, timeout=40)
        sleep(5)
    elif (transfer_protocol == 'http'):
        cmd = 'copy http://' + server_ip + '/test.txt flash:/' 
        device.execute(cmd, reply=dialog, prompt_recovery=True, timeout=40)
        sleep(5)
    elif (transfer_protocol == 'https'):
        cmd = 'copy https://' + server_ip + '/test.txt flash:/' 
        device.execute(cmd, reply=dialog, prompt_recovery=True, timeout=40)
        sleep(5)
    else:
        print("File transfer protocol not supported.")
        exit()


def file_transfer_client(protocol='', device='', 
                         mav6_ip='', ca_directory=''):
    secured = True if (protocol == 'https') else False
    if(file_on_flash(device, filename='test.txt')):
        del_from_flash(device, 'test.txt')

    # Create CA on Mav6 and create a signed cert for Mav6 https server
    if secured:
        ca_create_directory(ca_directory=ca_directory)
        ca_create_key(ca_directory=ca_directory, key_name='rootCA')
        ca_create_cert(ca_directory=ca_directory, key_name='rootCA', server_ip=mav6_ip)
        ca_create_key(ca_directory=ca_directory, key_name='server')
        ca_create_cert(ca_directory=ca_directory, key_name='server', server_ip=mav6_ip)

    embedded_server_process = Process(target=start_server, name='embeddedpserver', 
                                    args=(protocol, mav6_ip,))

    print('spawning ' + protocol + ' server process')
    embedded_server_process.start()
    sleep(5)

    # Add a trustpoint in the router that trusts the mav6 CA
    if secured:
        rtr_remove_trustpoint(device)
        rtr_add_trustpoint(device, ca_directory)
        rtr_authenticate_rootca(device, ca_directory)

    print("Attempting " + protocol + " file transfer")
    filetransfer_client_download(device=device, server_ip=mav6_ip, 
                                 transfer_protocol=protocol)
    sleep(2)
    embedded_server_process.kill()

    # Check to see if file transfer was successful and print message
    if (file_on_flash(device, filename='test.txt')):
        return True
    else:
        return False
    
def syslog_client(mav6_ip='', device='', protocol='syslog'):

    q = Queue()
    embedded_server_process = Process(target=start_notification_server, name='embeddedserver', 
                                    args=(protocol, mav6_ip, q,))

    print('spawning ' + protocol + ' server process')
    embedded_server_process.start()
    sleep(5)

    print("Triggering test device to send a syslog message")
    device.configure('')
    sleep(2)
    
    result=False
    while(not q.empty()):
        message = q.get()
        if "Configured from console" in message:
            result = True
    
    embedded_server_process.kill()
    sleep(2)
    return result
