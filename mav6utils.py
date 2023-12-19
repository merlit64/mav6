import os
import ipaddr
from termcolor import colored

# pyATS
from pyats.topology import loader
from pyats.utils.fileutils import FileUtils
from genie.libs.sdk.apis.iosxe import utils
from genie.libs.sdk.apis.iosxe.ntp.configure import *


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

    return dev


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


