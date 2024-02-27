######## IMPORTED LIBRARIES ########
### STANDARD LIBRARIES ###
from time import sleep
import random
from multiprocessing import Process, Queue
import ipaddress

### LOCAL FILES ###
from mav6utils import *
from embedded_fs import *
from ca import *

### PYPI LIBRARIES ###
from termcolor import colored

# pyATS
from pyats.topology import loader
from pyats.utils.fileutils import FileUtils
from genie.libs.sdk.apis.iosxe.ntp.configure import *
from unicon.eal.dialogs import Dialog, Statement

# for SNMP tests
from pysnmp.hlapi import *
#from pysnmp.carrier.asynsock.dgram import udp, udp6
#from pysnmp.entity import engine, config
#from pysnmp.entity.rfc3413 import ntfrcv, context, cmdrsp
from pysnmp.proto import rfc1902


def ping_client(device = '', device_to_ping='', test_device_os='iosxe'):
    # ping_client connects to the test device and tries to ping an
    #   ip address from there.
    # device - pyATS device object
    # device_to_ping - should be and ipv6 or ipv4 address
    # test_device_os - either 'iosxe' or 'nxos'

    if (ip_version(device_to_ping) == 6) and test_device_os == 'nxos':
        ping_result = device.ping6(device_to_ping)
    else:
        ping_result = device.ping(device_to_ping)
    print(ping_result)
    if ('!!!!' in ping_result or '5 packets received' in ping_result or '4 packets received' in ping_result ):
        return True
    else:
        return False


def perform_ssh_telnet(device, ip_address, username, password, protocol='ssh', test_device_os='iosxe'):
    # This function uses pyATS Dialogs to execute an ssh from device to a test server
    # device - pyATS device object
    # ip_address - ip address to ssh to, should be an Ubuntu server where mav6 lives
    # username/password - need I say more?
    # protocol - either 'ssh' or 'telnet' depending on the test being performed
    # test_device_os - either 'iosxe' or 'nxos'

    if protocol == 'ssh' and test_device_os == 'nxos':
        cmd = f'ssh {username}@{ip_address}'
    elif protocol == 'ssh' and test_device_os == 'iosxe':
        cmd = f'ssh -l {username} {ip_address}'
    else:
        cmd = f'telnet {ip_address}'
    #cmd += f'{ip_address}'

    ssh_telnet_dict = {
                'pass_timeout_expire_flag': False,
                'ssh_telnet_pass_case_flag': False,
                'enable_pass_flag': False
                }

    def pass_timeout_expire():
        ssh_telnet_dict['pass_timeout_expire_flag'] = True

    def send_yes(spawn):
        spawn.sendline('yes')

    def send_pass(spawn):
        spawn.sendline(password)

    def ssh_pass_case(spawn):
        ssh_telnet_dict['ssh_telnet_pass_case_flag'] = True
        # command to exit from the active ssh session from the device prompt itself.
        cli_command = 'exit'
        spawn.sendline(cli_command)
        
    def send_login(spawn):
        spawn.sendline(username)


    dialog = Dialog([
            Statement(pattern=r"Password:\s*timeout expired!",
                      action=pass_timeout_expire,
                      loop_continue=False),
            Statement(pattern=r"continue connecting (yes/no)?",
                      action=send_yes,
                      loop_continue=True),
            Statement(pattern=r"Password:",
                      action=send_pass,
                      loop_continue=True),
            Statement(pattern=r"password:",
                      action=send_pass,
                      loop_continue=True),
            Statement(pattern=r'Welcome to Ubuntu',
                      action=ssh_pass_case,
                      loop_continue=False),
            Statement(pattern=r"login:",
                      action=send_login,
                      loop_continue=True),
    ])

    try:
        device.execute(cmd, reply=dialog, prompt_recovery=True, timeout=40)

    except Exception as e:
        log.info(f"Error occurred while performing ssh or telnet : {e}")

    if ssh_telnet_dict['pass_timeout_expire_flag']:
        return False
    if ssh_telnet_dict['ssh_telnet_pass_case_flag']:
        return True
    

def telnet_client(device, server_ip, user, secret):
    # telnet client test function
    if (perform_ssh_telnet(device, server_ip, user, secret, 'telnet')):
        return True
    else:
        return False


def ssh_client(device, server_ip, user, secret, test_device_os='iosxe'):
    # ssh client test function
    if (perform_ssh_telnet(device, server_ip, user, secret, 'ssh', test_device_os)):
        return True
    else:
        return False


def ntp_client(device='', ntp_server='', test_device_os='iosxe'):
    # ntp_client tries to associate with an ntp server
    # device - pyATS device object
    # ntp_server - configure test device to connect to this ntp_server ip
    # test_device_os - either 'iosxe' or 'nxos'

    ntp_server = ipaddress.ip_address(ntp_server)
    show_run = device.execute("show run | include ntp")
    if test_device_os == 'nxos':
        show_ntp_assoc = device.execute("show ntp peer-status")
    else:
        show_ntp_assoc = device.execute("show ntp associations")
    if (ntp_server.compressed.upper() in show_run or ntp_server.compressed.lower() in show_run):
        if (('*~' + ntp_server.compressed.upper()) in show_ntp_assoc) or \
           (('*' + ntp_server.compressed.lower()) in show_ntp_assoc):
            print('NTP server configure and associated: \n' + show_ntp_assoc)
            return True
        else:
            print('NTP server configure but not associated: \n' + show_ntp_assoc)
            print('It may take more time for the ntp client to associate to the server.')
            print('or you may need to remove another ntp server and retest.')
            return False
    else:
        return False


def snmp_trap_client(snmp_version=2, comm_uname='', mav6_ip='', device='' ):
    # snmp_trap_client starts a separate snmp trap reciever process and triggers the test device
    #   to send a trap to it.  Returns true on success.
    # snmp_version - 2 or 3 type int
    # comm_uname - is the community for snmpv2 or uname 
    # mav6_ip - ipv4 or v6 address to bind the snmp trap reciever to
    # device - pyats device object of test device
    # protocol - 'syslog' for now, although this function may support others in the future
    # test_device_os - 'iosxe' or 'nxos;

    q = Queue()
    snmp_trap_receiver_process = Process(target=snmp_start_trap_receiver, name='snmptrapreceiver', 
                                         args=(q,snmp_version, mav6_ip,162,comm_uname))

    print('starting snmp trap receiver process, version ' + str(snmp_version))
    snmp_trap_receiver_process.start()
    sleep(5)
    
    # Trigger an event to send a trap
    print('Triggering Test Device to send a trap')
    if snmp_version == 2:
        device.configure ('banner motd c ' + str(random.randint(0,999999)) + ' c')
    elif snmp_version == 3:
        device.configure('')
        device.configure ('banner motd c ' + str(random.randint(0,999999)) + ' c')
    else:
        print('That version of SNMP does not exist')
        SystemExit()

    sleep(10)    

    # Check the queue created by the SNMP receiver for a trap sent by TEST_DEVICE
    received_snmp = False
    while(not q.empty()):
        message = q.get()
        if('netconf' in message):
            print('SNMP message arrived at receiver from TEST_DEVICE')
            received_snmp = True
        elif('1.3.6.1.4.1.9.9.43.2.0.2' in message):
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
        print('dest_filename_request')
    def vrf_request(spawn):
        spawn.sendline('default')
        print('vrf_request')
    dialog = Dialog([
        Statement(pattern=r"Destination filename",
                  action=dest_filename_request,
                  loop_continue=True),
        Statement(pattern=r"is considered",
                  action=vrf_request,
                  loop_continue=True)
    ])
    
    # send copy command
    if (transfer_protocol == 'tftp'):
        cmd = 'copy tftp://' + server_ip + '/test.txt bootflash:/test.txt' 
        device.execute(cmd, reply=dialog, prompt_recovery=True, timeout=40)
        sleep(5)
    elif (transfer_protocol == 'ftp'):
        cmd = 'copy ftp://paul:elephant060@' + server_ip + '/test.txt bootflash:/' 
        device.execute(cmd, reply=dialog, prompt_recovery=True, timeout=40)
        sleep(5)
    elif (transfer_protocol == 'http'):
        cmd = 'copy http://' + server_ip + '/test.txt bootflash:/' 
        device.execute(cmd, reply=dialog, prompt_recovery=True, timeout=40)
        sleep(5)
    elif (transfer_protocol == 'https'):
        cmd = 'copy https://' + server_ip + '/test.txt bootflash:/' 
        device.execute(cmd, reply=dialog, prompt_recovery=True, timeout=40)
        sleep(5)
    else:
        print("File transfer protocol not supported.")
        exit()


def file_transfer_client(protocol='', device='', 
                         mav6_ip='', ca_directory='', test_device_os='iosxe'):
    secured = True if (protocol == 'https') else False
    if(file_on_flash(device, filename='test.txt')):
        del_from_flash(device, 'test.txt', test_device_os)

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
    
def syslog_client(mav6_ip='', device='', protocol='syslog', test_device_os='iosxe'):
    # syslog_client starts a separate syslog server process and triggers the test device
    #   to send a syslog mesage to it.  Returns true on success.
    # mav6_ip - ipv4 or v6 address to bind the syslog server to
    # device - pyats device object of test device
    # protocol - 'syslog' for now, although this function may support others in the future
    # test_device_os - 'iosxe' or 'nxos;

    # Spawning syslog server process
    q = Queue()
    embedded_server_process = Process(target=start_notification_server, name='embeddedserver', 
                                    args=(protocol, mav6_ip, q,))
    print('spawning ' + protocol + ' server process')
    embedded_server_process.start()
    sleep(5)

    # Trigger test device to send a syslog message  Note: it took effort to get 
    #  nxos to send a message in a timely manner, rate-limit command was key
    print("Triggering test device to send a syslog message (up to 30s)")
    if test_device_os == 'nxos':
        # This will trigger for nxos
        sleep(2)
        device.configure('')
        sleep(20)
        device.configure('no logging rate-limit')
        sleep(2)
        device.configure('logging rate-limit')
        sleep(2)
        if q.empty():
            print('Test failed, trying again (up to 30s)')
            sleep(20)
            device.configure('no logging rate-limit')
            sleep(2)
            device.configure('logging rate-limit')
            sleep(2)
    else:
        # This will trigger for iosxe
        device.configure('')
    
    result=False
    while(not q.empty()):
        message = q.get()
        if "Configured from" in message:
            result = True
            break
    
    embedded_server_process.kill()
    sleep(2)
    return result
