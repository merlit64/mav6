######## IMPORTED LIBRARIES ########
### STANDARD LIBRARIES ###
from time import sleep, ctime
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
test_array = np.array([["Test", "Result"],
                       ["PING_SERVER", "N/A"],
                       ["TELNET_SERVER", "N/A"],
                       ["SSH_SERVER", "N/A"],
                       ["SCP_SERVER", "N/A"],
                       ["TFTP_SERVER", "N/A"],
                       ["HTTP_SERVER", "N/A"],
                       ["HTTPS_SERVER", "N/A"],
                       ["SNMPV2_READ", "N/A"],
                       ["SNMPV2_WRITE", "N/A"],
                       ["SNMPV3_READ", "N/A"],
                       ["SNMPV3_WRITE", "N/A"],
                       ["NTP_SERVER", "N/A"],
                       ["PING_CLIENT", "N/A"],
                       ["TELNET_CLIENT", "N/A"],
                       ["SSH_CLIENT", "N/A"],
                       ["TFTP_CLIENT", "N/A"],
                       ["FTP_CLIENT", "N/A"],
                       ["HTTP_CLIENT", "N/A"],
                       ["HTTPS_CLIENT", "N/A"],
                       ["SNMPV2_TRAP", "N/A"],
                       ["SNMPV3_TRAP", "N/A"],
                       ["NTP_CLIENT", "N/A"]])

# Build pyATS Testbed environment from the secrets file configuration settings
testbed_data = { 'TEST_DEVICE':TEST_DEVICE, 'TEST_DEVICE_HOSTNAME':TEST_DEVICE_HOSTNAME, 
                 'CLI_USER':CLI_USER, 'CLI_PASS':CLI_PASS}
render_testbed(testbed_filename='pyATS/testbed.yaml', testbed_data=testbed_data)

print(colored('\n\nInitiating TEST_DEVICE connection (approx 30s)', "yellow"))
mav6_ip = MAV6_IPV4 if ip_version(TEST_DEVICE) == 4 else MAV6_IPV6
device = connect_host(TEST_DEVICE, TEST_DEVICE_HOSTNAME, CLI_USER, CLI_PASS, protocol='ssh')
if (device == None):
    print(colored('Fatal Error: You must enable SSH to the device in order to send configurations and run tests', 'red'))
    exit()



# Ping Server Test
if PING_SERVER:
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
if TELNET_SERVER:
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
if SSH_SERVER:
    msg = '\nAttempting ssh to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    ssh_test_device = connect_host(TEST_DEVICE, TEST_DEVICE_HOSTNAME, 
                                   
                                   
                                   CLI_USER, CLI_PASS, 'ssh')
    
    if (ssh_test_device == None):
        print(colored("SSH Server Test Failed", "red"))
        test_array[3][1] = "FAIL"
    else:
        print(colored("SSH Server Test Success", "green"))
        test_array[3][1] = "PASS"
    ssh_test_device.disconnect()
    
# SCP Server Test
if SCP_SERVER:
    # Create a txt file to transfer on the router
    command = 'show netconf counters | append from_testdevice.txt'
    device.execute(command)
    
    # configure the test device as an scp server
    device.configure('ip scp server enable')

    msg = '\nAttempting SCP server download from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to ' + mav6_ip
    print(colored(msg, "yellow"))
    result = tftpscp_server_download(TEST_DEVICE, port=443, filename='from_testdevice.txt',
                            username=CLI_USER, password=CLI_PASS)

    if (result):
        print(colored("SCP Server Test Successful\n\n", "green"))
        test_array[4][1] = "PASS"
    else:
        print(colored("SCP Server Test Failed\n\n", "red"))
        test_array[4][1] = "FAIL"
        
# TFTP Server Test

if TFTP_SERVER:
    # Connect to device and create a file on the flash
    command = 'show netconf counters | append from_testdevice.txt'
    device.execute(command)
    
    # configure the test device as a tftp-server
    device.configure('tftp-server flash:from_testdevice.txt')
    
    # Attempt download
    msg = '\nAttempting TFTP server download from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to ' + mav6_ip
    print(colored(msg, "yellow"))
    result = tftpscp_server_download(TEST_DEVICE, port=69, filename='from_testdevice.txt')

    if (result):
        print(colored("TFTP Server Test Successful\n\n", "green"))
        test_array[5][1] = "PASS"
    else:
        print(colored("TFTP Server Test Failed\n\n", "red"))
        test_array[5][1] = "FAIL"

# HTTP Server Test
if HTTP_SERVER:
    # Configure device
    device.configure('ip http server')
    device.configure('no ip http secure-server')
    sleep(10)

    msg = '\nAttempting HTTP connection to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))
    result = http_test(TEST_DEVICE)

    if (result=='200'):
        print(colored("HTTP Server Test Success", "green"))
        test_array[6][1] = "PASS"
    else:
        print(colored("HTTP Server Test Failed", "red"))
        test_array[6][1] = "FAIL"
        

# HTTPS Server Test
if HTTPS_SERVER:
    # Configure device
    device.configure('ip http server')
    device.configure('ip http secure-server')
    sleep(10)

    msg = '\nAttempting HTTPS connection to ' + TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))
    result = http_test(TEST_DEVICE, verify=False)
    
    if (result=='200'):
        print(colored("HTTPS Server Test Success", "green"))
        test_array[7][1] = "PASS"
    else:
        print(colored("HTTPS Server Test Failed", "red"))
        test_array[7][1] = "FAIL"

# SNMP v2 Read Test
if SNMPV2_READ:
    # Configure device
    device.configure('snmp-server community ' + COM_RO + ' ro')

    msg = '\nAttempting SNMPv2 read request to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))
    result = snmp_call( TEST_DEVICE, 'IF-MIB', 'ifAlias', 1, version = "v2", 
              action = "read", community=COM_RO )

    if (result):
        print(colored("SNMP V2 Read Test Success", "green"))
        test_array[8][1] = "PASS"
    else:
        print(colored("SNMP V2 Read Test Failed", "red"))
        test_array[8][1] = "FAIL"

# SNMP v2 Write Test
if SNMPV2_WRITE:
    # Configure device
    device.configure('snmp-server community ' + COM_RW + ' rw')

    msg = '\nAttempting SNMPv2 write  to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))
    result = snmp_call( TEST_DEVICE, 'SNMPv2-MIB', 'sysContact', 0, mib_value="mav6 snmpv2test worked", 
              version = "v2", action = "write", community=COM_RW )

    if (result):
        print(colored("SNMP V2 Write Test Success", "green"))
        test_array[9][1] = "PASS"
    else:
        print(colored("SNMP V2 Write Test Failed", "red"))
        test_array[9][1] = "FAIL"

# SNMP v3 Read Test
if SNMPV3_READ:
    # Configure device
    device.configure('no snmp-server user mav6user mav6group v3')
    device.configure('no snmp-server group mav6group v3 priv')
    device.configure('snmp-server group mav6group v3 priv')
    command = 'snmp-server user ' + SNMP_USER + ' mav6group v3 auth sha ' + \
                AUTH_KEY + ' priv aes 128 ' + PRIV_KEY
    device.configure(command)
    #device.configure('snmp-server enable traps')
    #device.configure('snmp-server enable traps config')
    #device.configure('snmp-server host ' + mav6_ip + ' ver 3 noauth mav6user')
    
    msg = '\nAttempting SNMPv3 read request to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    result = snmp_call( TEST_DEVICE, 'IF-MIB', 'ifInOctets', 1, version = "v3", action = "read", 
          userName=SNMP_USER, authKey=AUTH_KEY, privKey=PRIV_KEY  )

    if (result):
        print(colored("SNMP V3 Read Test Success", "green"))
        test_array[10][1] = "PASS"
    else:
        print(colored("SNMP V3 Read Test Failed", "red"))
        test_array[10][1] = "FAIL"

# SNMP v3 Write Test
if SNMPV3_WRITE:
    # Configure device
    device.configure('no snmp-server user mav6user mav6group v3')
    device.configure('no snmp-server group mav6group v3 priv')
    device.configure('snmp-server view v3view iso included')
    device.configure('snmp-server group mav6group v3 priv write v3view')
    command = 'snmp-server user ' + SNMP_USER + ' mav6group v3 auth sha ' + \
                AUTH_KEY + ' priv aes 128 ' + PRIV_KEY
    device.configure(command)
    #device.configure('snmp-server enable traps')
    #device.configure('snmp-server enable traps config')
    #device.configure('snmp-server host ' + mav6_ip + ' ver 3 noauth mav6user')

    msg = '\nAttempting SNMPv3 write to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    result = snmp_call( TEST_DEVICE, 'IF-MIB', 'ifAlias', 1, mib_value="mav6", version = "v3", action = "write", 
          userName=SNMP_USER, authKey=AUTH_KEY, privKey=PRIV_KEY  )

    if (result):
        print(colored("SNMP V3 Write Test Success", "green"))
        test_array[11][1] = "PASS"
    else:
        print(colored("SNMP V3 Write Test Failed", "red"))
        test_array[11][1] = "FAIL"

# NTP v4 Server Test
if NTP_SERVER:
    # Configure device
    device.configure('ntp master')

    # Send NTP version 4 request over ipv4 or ipv6
    msg = '\nAttempting NTPv4 connection  to TEST_DEVICE: ' + \
           TEST_DEVICE + ' from mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

    result = ntp_call(ip=TEST_DEVICE)

    if (result):
        print(colored("NTP Server Test Success", "green"))
        test_array[12][1] = "PASS"
    else:
        print(colored("NTP Server Test Failed", "red"))
        test_array[12][1] = "FAIL"

### CLIENT TESTS ###
print("\nExecuting Client Tests (where test box acts as the client):\n\n")

# Ping Client Test
if PING_CLIENT:
    msg = '\nAttempting to  ping mav6: ' + \
           mav6_ip + ' from TEST_DEVICE: ' + TEST_DEVICE
    print(colored(msg, "yellow"))
    
    result = ping_client(device, device_to_ping=mav6_ip)

    if (result):
        print(colored("Ping Client Test Successful\n\n", "green"))
        test_array[13][1] = "PASS"
    else:
        print(colored("Ping Client Test Failed\n\n", "red"))
        test_array[13][1] = "FAIL"

# Telnet Client Test
if TELNET_CLIENT:
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
if SSH_CLIENT:
    msg = '\nAttempting to SSH from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to mav6: ' + mav6_ip
    print(colored(msg, "yellow"))
    
    result = ssh_client(device, mav6_ip, MAV6_USER, MAV6_PASS)

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
if TFTP_CLIENT:
    msg = '\nAttempting TFTP file transfer from mav6: ' + \
           mav6_ip + ' to TEST_DEVICE: ' + TEST_DEVICE
    print(colored(msg, "yellow"))

    result = file_transfer_client(protocol='tftp', device=device, 
                                  mav6_ip=mav6_ip)
    if (result):
        print(colored("TFTP Client Test Successful\n\n", "green"))
        test_array[16][1] = "PASS"
    else:
        print(colored("TFTP Client Test Failed\n\n", "red"))
        test_array[16][1] = "FAIL"

# FTP Client test
if FTP_CLIENT:
    msg = '\nAttempting  FTP file transfer from mav6: ' + \
           mav6_ip + ' to TEST_DEVICE: ' + TEST_DEVICE
    print(colored(msg, "yellow"))
    result = file_transfer_client(protocol='ftp', device=device, mav6_ip=mav6_ip)

    if (result):
        print(colored("FTP Client Test Successful\n\n", "green"))
        test_array[17][1] = "PASS"
    else:
        print(colored("FTP Client Test Failed\n\n", "red"))
        test_array[17][1] = "FAIL"

# HTTP client Test
if HTTP_CLIENT:
    msg = '\nAttempting HTTP file transfer from mav6: ' + \
           mav6_ip + ' to TEST_DEVICE: ' + TEST_DEVICE
    print(colored(msg, "yellow"))

    result = file_transfer_client(protocol='http', device=device, mav6_ip=mav6_ip)

    if (result):
        print(colored("HTTP Client Test Successful\n\n", "green"))
        test_array[18][1] = "PASS"
    else:
        print(colored("HTTP Client Test Failed\n\n", "red"))
        test_array[18][1] = "FAIL"

# HTTPS client Test

if HTTPS_CLIENT:
    msg = '\nAttempting HTTPS file transfer from mav6: ' + \
           mav6_ip + ' to TEST_DEVICE: ' + TEST_DEVICE
    print(colored(msg, "yellow"))

    result = file_transfer_client(protocol='https', device=device, 
                                  mav6_ip=mav6_ip, ca_directory=CA_DIRECTORY)
    if (result):
        print(colored("HTTPS Client Test Successful\n\n", "green"))
        test_array[19][1] = "PASS"
    else:
        print(colored("HTTPS Client Test Failed\n\n", "red"))
        test_array[19][1] = "FAIL"

# SNMP v2 Trap Test
if SNMPV2_TRAP:
    device.configure('snmp-server community ' + COM_RW + ' rw')
    device.configure('snmp-server enable traps')
    device.configure('snmp-server enable traps config')
    device.configure('snmp-server host ' + mav6_ip + ' traps ' + COM_RW)

    msg = '\nAttempting to send an SNMPv2 trap from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to mav6: ' + mav6_ip
    print(colored(msg, "yellow"))

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
if SNMPV3_TRAP:
    # Configure device
    device.configure('no snmp-server user mav6user mav6group v3')
    device.configure('no snmp-server group mav6group v3 priv')
    device.configure('snmp-server group mav6group v3 priv')
    command = 'snmp-server user mav6user mav6group v3 auth sha ' + AUTH_KEY + \
               ' priv aes 128 ' + PRIV_KEY
    device.configure(command)
    device.configure('snmp-server enable traps')
    device.configure('snmp-server enable traps config')
    device.configure('snmp-server host ' + mav6_ip + ' ver 3 noauth mav6user')

    msg = '\nAttempting to send an SNMPv3 trap from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to mav6: ' + mav6_ip
    print(colored(msg, "yellow"))
    
    result = snmp_trap_client(snmp_version=3, comm_uname=COM_RW, mav6_ip=mav6_ip, 
                              device=device)

    # Print Test results to screen
    if (result):
        print(colored("SNMPv3 Trap Test Successful\n\n", "green"))
        test_array[21][1] = "PASS"
    else:
        print(colored("SNMPv3 Trap Test Failed\n\n", "red"))
        test_array[21][1] = "FAIL"
    
# NTP v4 Client Test
if NTP_CLIENT:
    msg = '\nAttempting an NTPv4 connection from TEST_DEVICE: ' + \
           TEST_DEVICE + ' to NTP_TEST_SERVER: ' + NTP_TEST_SERVER
    print(colored(msg, "yellow"))
    
    result = ntp_client(device, NTP_TEST_SERVER)

    if (result):
        print(colored("NTPv4 Test Successful\n\n", "green"))
        test_array[22][1] = "PASS"
    else:
        print(colored("NTPv4 Test Failed\n\n", "red"))
        test_array[22][1] = "FAIL"
        
server_test_results(test_array)
