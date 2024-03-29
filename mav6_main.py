######## IMPORTED LIBRARIES ########
### STANDARD LIBRARIES ###
from time import sleep, ctime
from jinja2 import Template
import yaml
import os

### LOCAL FILES ###
from secrets_1 import *
from test_configuration import *
from server import *
from client import *
from mav6utils import *
from embedded_fs import *

### PYPI LIBRARIES ###
from termcolor import colored


######## MAIN PROGRAM ########

# Note: ALL comments are made from the perspective of the test device
# I.E. Telnet server test means the Test device is acting as the TFTP Server

#initialize numpy array for test results output
test_array = test_array_init()

# Render pyATS Testbed yaml from the secrets file configuration settings
mav6_ip = MAV6_IPV4 if ip_version(TEST_DEVICE) == 4 else MAV6_IPV6

testbed_data = { 'TEST_DEVICE':TEST_DEVICE, 'TEST_DEVICE_HOSTNAME':TEST_DEVICE_HOSTNAME, 
                 'CLI_USER':CLI_USER, 'CLI_PASS':CLI_PASS, 'COM_RO':COM_RO, 'COM_RW':COM_RW,
                 'SNMP_USER':SNMP_USER, 'AUTH_KEY':AUTH_KEY, 'PRIV_KEY':PRIV_KEY, 
                 'mav6_ip':mav6_ip, 'TEST_DEVICE_OS':TEST_DEVICE_OS, 'NTP_TEST_SERVER':NTP_TEST_SERVER}
render_testbed(testbed_filename='pyATS/testbed.yaml', testbed_data=testbed_data)

# Render device pack os.yaml file and data from secrets file into a device configuraiton dictionary
# This will help us send device configuration to the test device before each test that 
# requires a certain configuration
dp_filename = 'device_packs/' + TEST_DEVICE_OS + '.yaml'
dp_file = open(dp_filename, 'r')
dp_template_str = dp_file.read()
dp_file.close()
dp = Template(dp_template_str)
dp_yaml_str = dp.render(testbed_data)

# The config_dict is keyed on the test name 'TFTP_SERVER' for example
# and has a corresponding td_config which is a configuration that must be
# pushed to the device before the test commences
config_dict=yaml.safe_load(dp_yaml_str)
config_dict = config_dict['tests']


print(colored('\n\nInitiating TEST_DEVICE connection (approx 30s)', "blue"))
device = connect_host(TEST_DEVICE, TEST_DEVICE_HOSTNAME, CLI_USER, CLI_PASS, protocol='ssh')
if (device == None):
    print(colored('Fatal Error: You must enable SSH to the device in order to send configurations and run tests', 'red'))
    exit()


### SERVER TESTS ###
print(colored("\nExecuting Server Tests (where test box acts as the server):\n", "blue"))

# Ping Server Test
if PING_SERVER and 'PING_SERVER' in config_dict and config_dict['PING_SERVER']:
    # Opening message for the test
    msg = '\nAttempting Ping of TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    result = ping_host(TEST_DEVICE)
    
    if (result):
        print(colored("Ping Server Test Success", "green"))
        test_array[1][1] = "PASS"
    else:
        print(colored("Ping Server Test Failed", "red"))
        test_array[1][1] = "FAIL"
# Telnet Server Test
if TELNET_SERVER and 'TELNET_SERVER' in config_dict and config_dict['TELNET_SERVER']:
    # Opening message for the test
    msg = '\nAttempting telnet to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))
    
    telnet_test_device = connect_host(TEST_DEVICE, TEST_DEVICE_HOSTNAME, 
                                      CLI_USER, CLI_PASS, 'telnet')

    if (telnet_test_device == None):
        print(colored("Telnet Server Test Failed", "red"))
        test_array[2][1] = "FAIL"
    else:
        print(colored("Telnet Server Test Success", "green"))
        test_array[2][1] = "PASS"
    telnet_test_device.disconnect()
        
    # Set device back to None so we connect via ssh for future tests

# SSH Server Test
if SSH_SERVER and 'SSH_SERVER' in config_dict and config_dict['SSH_SERVER']:
    # Opening message for the test
    msg = '\nAttempting ssh to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    ssh_test_device = connect_host(TEST_DEVICE, TEST_DEVICE_HOSTNAME, CLI_USER, CLI_PASS, 'ssh')
    
    if (ssh_test_device == None):
        print(colored("SSH Server Test Failed", "red"))
        test_array[3][1] = "FAIL"
    else:
        print(colored("SSH Server Test Success", "green"))
        test_array[3][1] = "PASS"
    ssh_test_device.disconnect()
    
# SCP Server Test
if SCP_SERVER and 'SCP_SERVER' in config_dict and config_dict['SCP_SERVER']:
    # Opening message for the test
    msg = '\nAttempting SCP server download from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to ' + mav6_ip
    print(colored(msg, "yellow"))
   
    # configure the test device as an scp server
    configure_test_device(device, config_dict, test='SCP_SERVER')

    result = tftpscp_server_download(TEST_DEVICE, port=443, filename='from_testdevice.txt',
                            username=CLI_USER, password=CLI_PASS)

    if (result):
        print(colored("SCP Server Test Successful\n\n", "green"))
        test_array[4][1] = "PASS"
    else:
        print(colored("SCP Server Test Failed\n\n", "red"))
        test_array[4][1] = "FAIL"
        
# TFTP Server Test
if TFTP_SERVER and 'TFTP_SERVER' in config_dict and config_dict['TFTP_SERVER']:
    # Opening message for the test
    msg = '\nAttempting TFTP server download from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to ' + mav6_ip
    print(colored(msg, "yellow"))

    # configure the test device as a tftp-server
    configure_test_device(device, config_dict, test='TFTP_SERVER')
    
    # Attempt download
    result = tftpscp_server_download(TEST_DEVICE, port=69, filename='from_testdevice.txt')

    if (result):
        print(colored("TFTP Server Test Successful\n\n", "green"))
        test_array[5][1] = "PASS"
    else:
        print(colored("TFTP Server Test Failed\n\n", "red"))
        test_array[5][1] = "FAIL"

# HTTP Server Test
if HTTP_SERVER and 'HTTP_SERVER' in config_dict and config_dict['HTTP_SERVER']:
    # Opening message for the test
    msg = '\nAttempting HTTP connection to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    # Configure the test device as an http server
    configure_test_device(device, config_dict, test='HTTP_SERVER')
    sleep(10)

    result = http_test(TEST_DEVICE)

    if (result=='200'):
        print(colored("HTTP Server Test Success", "green"))
        test_array[6][1] = "PASS"
    else:
        print(colored("HTTP Server Test Failed", "red"))
        test_array[6][1] = "FAIL"
        

# HTTPS Server Test
if HTTPS_SERVER and 'HTTPS_SERVER' in config_dict and config_dict['HTTPS_SERVER']:
    # Opening message for the test
    msg = '\nAttempting HTTPS connection to ' + TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    # Configure the test device as an https server
    configure_test_device(device, config_dict, test='HTTPS_SERVER')
    sleep(10)

    result = http_test(TEST_DEVICE, verify=False)
    
    if (result=='200'):
        print(colored("HTTPS Server Test Success", "green"))
        test_array[7][1] = "PASS"
    else:
        print(colored("HTTPS Server Test Failed", "red"))
        test_array[7][1] = "FAIL"

# SNMP v2 Read Test
if SNMPV2_READ and 'SNMPV2_READ' in config_dict and config_dict['SNMPV2_READ']:
    # Opening message for the test
    msg = '\nAttempting SNMPv2 read request to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    # Configure the test device to service snmpv2 read requests
    configure_test_device(device, config_dict, test='SNMPV2_READ')

    result = snmp_call( TEST_DEVICE, 'SNMPv2-MIB', 'sysContact', 0, version = "v2", 
              action = "read", community=COM_RO )

    if (result):
        print(colored("SNMP V2 Read Test Success", "green"))
        test_array[8][1] = "PASS"
    else:
        print(colored("SNMP V2 Read Test Failed", "red"))
        test_array[8][1] = "FAIL"

# SNMP v2 Write Test
if SNMPV2_WRITE and 'SNMPV2_WRITE' in config_dict and config_dict['SNMPV2_WRITE']:
    # Opening message for the test
    msg = '\nAttempting SNMPv2 write  to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    # Configure the test device to service snmpv2 write requests
    configure_test_device(device, config_dict, test='SNMPV2_WRITE')

    result = snmp_call( TEST_DEVICE, 'SNMPv2-MIB', 'sysContact', 0, mib_value="mav6 SNMPV2_WRITE successful", 
              version = "v2", action = "write", community=COM_RW )

    if (result):
        print(colored("SNMP V2 Write Test Success", "green"))
        test_array[9][1] = "PASS"
    else:
        print(colored("SNMP V2 Write Test Failed", "red"))
        test_array[9][1] = "FAIL"

# SNMP v3 Read Test
if SNMPV3_READ and 'SNMPV3_READ' in config_dict and config_dict['SNMPV3_READ']:
    # Opening message for the test
    msg = '\nAttempting SNMPv3 read request to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    # Configure the test device to service snmpv3 read requests
    configure_test_device(device, config_dict, test='SNMPV3_READ')
    
    result = snmp_call( TEST_DEVICE, 'SNMPv2-MIB', 'sysContact', 0, version = "v3", action = "read", 
          userName=SNMP_USER, authKey=AUTH_KEY, privKey=PRIV_KEY  )

    if (result):
        print(colored("SNMP V3 Read Test Success", "green"))
        test_array[10][1] = "PASS"
    else:
        print(colored("SNMP V3 Read Test Failed", "red"))
        test_array[10][1] = "FAIL"

# SNMP v3 Write Test
if SNMPV3_WRITE and 'SNMPV3_WRITE' in config_dict and config_dict['SNMPV3_WRITE']:
    # Opening message for the test
    msg = '\nAttempting SNMPv3 write to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    # Configure the test device to service snmpv3 write requests
    configure_test_device(device, config_dict, test='SNMPV3_WRITE')

    result = snmp_call( TEST_DEVICE, 'SNMPv2-MIB', 'sysContact', 0, mib_value="mav6 SNMPV3_WRITE successful", 
                       version = "v3", action = "write", userName=SNMP_USER, authKey=AUTH_KEY, privKey=PRIV_KEY)

    if (result):
        print(colored("SNMP V3 Write Test Success", "green"))
        test_array[11][1] = "PASS"
    else:
        print(colored("SNMP V3 Write Test Failed", "red"))
        test_array[11][1] = "FAIL"

# NTP v4 Server Test
if NTP_SERVER and 'NTP_SERVER' in config_dict and config_dict['NTP_SERVER']:
    # Opening message for the test
    msg = '\nAttempting NTPv4 connection  to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    # Configure the test device to act as an NTP server
    configure_test_device(device, config_dict, test='NTP_SERVER')

    # Send NTP version 4 request over ipv4 or ipv6
    result = ntp_call(ip=TEST_DEVICE)

    if (result):
        print(colored("NTP Server Test Success", "green"))
        test_array[12][1] = "PASS"
    else:
        print(colored("NTP Server Test Failed", "red"))
        test_array[12][1] = "FAIL"

### CLIENT TESTS ###
print(colored("\nExecuting Client Tests (where test box acts as the client):\n", "blue"))

# Ping Client Test
if PING_CLIENT and 'PING_CLIENT' in config_dict and config_dict['PING_CLIENT']:
    # Opening message for the test
    msg = '\nAttempting to  ping mav6: ' + \
           mav6_ip + ' from TEST_DEVICE: ' + TEST_DEVICE
    print(colored(msg, "yellow"))
    
    result = ping_client(device, device_to_ping=mav6_ip, test_device_os=TEST_DEVICE_OS)

    if (result):
        print(colored("Ping Client Test Successful\n\n", "green"))
        test_array[13][1] = "PASS"
    else:
        print(colored("Ping Client Test Failed\n\n", "red"))
        test_array[13][1] = "FAIL"

# Telnet Client Test
if TELNET_CLIENT and 'TELNET_CLIENT' in config_dict and config_dict['TELNET_CLIENT']:
    # Opening message for the test
    msg = '\nAttempting to telnet from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    result = telnet_client(device, mav6_ip, MAV6_USER, MAV6_PASS)
   
    if (result):
        print(colored("Telnet Client Test Successful\n\n", "green"))
        test_array[14][1] = "PASS"
    else:
        print(colored("Telnet Client Test Failed\n\n", "red"))
        test_array[14][1] = "FAIL"
 
# SSH Client Test
if SSH_CLIENT and 'SSH_CLIENT' in config_dict and config_dict['SSH_CLIENT']:
    # Opening message for the test
    msg = '\nAttempting to SSH from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to mav6: ' + mav6_ip
    print(colored(msg, "yellow"))
    
    result = ssh_client(device, mav6_ip, MAV6_USER, MAV6_PASS, TEST_DEVICE_OS)

    if (result):
        print(colored("SSH Client Test Successful\n\n", "green"))
        test_array[15][1] = "PASS"
    else:
        print(colored("SSH Client Test Failed\n\n", "red"))
        test_array[15][1] = "FAIL"

# SCP client Test
# Linux Server
# IOSXE Device

# TFTP client Test
if TFTP_CLIENT and 'TFTP_CLIENT' in config_dict and config_dict['TFTP_CLIENT']:
    # Opening message for the test
    msg = '\nAttempting TFTP file transfer from mav6: ' + \
           mav6_ip + ' to TEST_DEVICE: ' + TEST_DEVICE
    print(colored(msg, "yellow"))

    result = file_transfer_client(protocol='tftp', device=device, 
                                  mav6_ip=mav6_ip, test_device_os=TEST_DEVICE_OS)
    if (result):
        print(colored("TFTP Client Test Successful\n\n", "green"))
        test_array[16][1] = "PASS"
    else:
        print(colored("TFTP Client Test Failed\n\n", "red"))
        test_array[16][1] = "FAIL"

# FTP Client test
if FTP_CLIENT and 'FTP_CLIENT' in config_dict and config_dict['FTP_CLIENT']:
    # Opening message for the test
    msg = '\nAttempting  FTP file transfer from mav6: ' + \
           mav6_ip + ' to TEST_DEVICE: ' + TEST_DEVICE
    print(colored(msg, "yellow"))
    result = file_transfer_client(protocol='ftp', device=device, mav6_ip=mav6_ip, 
                                  test_device_os=TEST_DEVICE_OS)

    if (result):
        print(colored("FTP Client Test Successful\n\n", "green"))
        test_array[17][1] = "PASS"
    else:
        print(colored("FTP Client Test Failed\n\n", "red"))
        test_array[17][1] = "FAIL"

# HTTP client Test
if HTTP_CLIENT and 'HTTP_CLIENT' in config_dict and config_dict['HTTP_CLIENT']:
    # Opening message for the test
    msg = '\nAttempting HTTP file transfer from mav6: ' + \
           mav6_ip + ' to TEST_DEVICE: ' + TEST_DEVICE
    print(colored(msg, "yellow"))

    result = file_transfer_client(protocol='http', device=device, mav6_ip=mav6_ip, 
                                  test_device_os=TEST_DEVICE_OS)

    if (result):
        print(colored("HTTP Client Test Successful\n\n", "green"))
        test_array[18][1] = "PASS"
    else:
        print(colored("HTTP Client Test Failed\n\n", "red"))
        test_array[18][1] = "FAIL"

# HTTPS client Test

if HTTPS_CLIENT and 'HTTPS_CLIENT' in config_dict and config_dict['HTTPS_CLIENT']:
    # Opening message for the test
    msg = '\nAttempting HTTPS file transfer from mav6: ' + \
           mav6_ip + ' to TEST_DEVICE: ' + TEST_DEVICE
    print(colored(msg, "yellow"))

    result = file_transfer_client(protocol='https', device=device, 
                                  mav6_ip=mav6_ip, ca_directory=CA_DIRECTORY,
                                  test_device_os=TEST_DEVICE_OS)
    if (result):
        print(colored("HTTPS Client Test Successful\n\n", "green"))
        test_array[19][1] = "PASS"
    else:
        print(colored("HTTPS Client Test Failed\n\n", "red"))
        test_array[19][1] = "FAIL"

# SNMP v2 Trap Test
if SNMPV2_TRAP and 'SNMPV2_TRAP' in config_dict and config_dict['SNMPV2_TRAP']:
    # Opening message for the test
    msg = '\nAttempting to send an SNMPv2 trap from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    # Configure test device to send snmpv2 traps
    configure_test_device(device, config_dict, test='SNMPV2_TRAP')
    sleep(30)

    result = snmp_trap_client(snmp_version=2, comm_uname=COM_RW, mav6_ip=mav6_ip, 
                              device=device)

    # Print Test results to screen
    if (result):
        print(colored("SNMPv2 Trap Test Successful\n\n", "green"))
        test_array[20][1] = "PASS"
    else:
        print(colored("SNMPv2 Trap Test Failed\n\n", "red"))
        test_array[20][1] = "FAIL"

# SNMP v3 Trap Test
if SNMPV3_TRAP and 'SNMPV3_TRAP' in config_dict and config_dict['SNMPV3_TRAP']:
    # Opening message for the test
    msg = '\nAttempting to send an SNMPv3 trap from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to mav6: ' + mav6_ip
    print(colored(msg, "yellow"))
    
    # Configure test device to send snmpv3 traps
    configure_test_device(device, config_dict, test='SNMPV3_TRAP')
    sleep(30)

    result = snmp_trap_client(snmp_version=3, comm_uname=SNMP_USER, mav6_ip=mav6_ip, 
                              device=device)

    # Print Test results to screen
    if (result):
        print(colored("SNMPv3 Trap Test Successful\n\n", "green"))
        test_array[21][1] = "PASS"
    else:
        print(colored("SNMPv3 Trap Test Failed\n\n", "red"))
        test_array[21][1] = "FAIL"
    
# NTP v4 Client Test
if NTP_CLIENT and 'NTP_CLIENT' in config_dict and config_dict['NTP_CLIENT']:
    # Opening message for the test
    msg = '\nAttempting an NTPv4 connection from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to NTP_TEST_SERVER: ' + NTP_TEST_SERVER
    print(colored(msg, "yellow"))

    # Configure test device as ntp client
    configure_test_device(device, config_dict, test='NTP_CLIENT')
    sleep(30)

    result = ntp_client(device, NTP_TEST_SERVER, test_device_os=TEST_DEVICE_OS)

    if (result):
        print(colored("NTPv4 Test Successful\n\n", "green"))
        test_array[22][1] = "PASS"
    else:
        print(colored("NTPv4 Test Failed\n\n", "red"))
        test_array[22][1] = "FAIL"

# Syslog Client Test
if SYSLOG_CLIENT and 'SYSLOG_CLIENT' in config_dict and config_dict['SYSLOG_CLIENT']:
    # Opening message for the test
    msg = '\nAttempting to send a Syslog message from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to mav6: ' + mav6_ip
    print(colored(msg, "yellow"))
    
    # Configure test device to send syslog mesages
    if (ip_version(mav6_ip) == 6):
        configure_test_device(device, config_dict, test='SYSLOG_CLIENT', td_configure='td_ipv6_configure')
        #device.configure('logging host ipv6 ' + mav6_ip )
    else:
        configure_test_device(device, config_dict, test='SYSLOG_CLIENT', td_configure='td_ipv4_configure')
        #device.configure('logging host ' + mav6_ip )

    result = syslog_client( mav6_ip=mav6_ip, device=device, protocol='syslog', 
                           test_device_os=TEST_DEVICE_OS)

    # Print Test results to screen
    if (result):
        print(colored("Syslog Client Test Successful\n\n", "green"))
        test_array[23][1] = "PASS"
    else:
        print(colored("Syslog Client Test Failed\n\n", "red"))
        test_array[23][1] = "FAIL"
  
        
server_test_results(test_array)
