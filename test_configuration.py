# Server Tests
PING_SERVER = False
TELNET_SERVER = False
SSH_SERVER = False
SCP_SERVER = False
TFTP_SERVER = False
HTTP_SERVER = False
HTTPS_SERVER = False
SNMPV2_READ = False
SNMPV2_WRITE = False
SNMPV3_READ = False
SNMPV3_WRITE = False
NTP_SERVER = False

# Client Tests
PING_CLIENT = True
TELNET_CLIENT = True
SSH_CLIENT = True
SCP_CLIENT = False
TFTP_CLIENT = False
FTP_CLIENT = False
HTTP_CLIENT = False
HTTPS_CLIENT = False
SNMPV2_TRAP = False
SNMPV3_TRAP = False
NTP_CLIENT = True

# Local Servers available for client tests
PYATS_TESTBED = 'pyATS/testbed.yaml'
LOCAL_DEVICE = '10.1.1.1'
CA_DIRECTORY = 'keys_and_certs'
CA_CERT_NAME = 'rootCA'

