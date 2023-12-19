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
# If you are using mav6's http server you must build a key file and cert
# 
SNMPV2_TRAP = False
SNMPV3_TRAP = False
NTP_CLIENT = True

# Local Servers available for client tests
#USE_LOCAL_TELNET_SERVER = NA
USE_LOCAL_SSH_SERVER = True
USE_LOCAL_SCP_SERVER = True
#USE_LOCAL_TFTP_SERVER = NA
# Below is used for FTP and TFTP
FILE_TRANSFER_SERVER_PATH = '/home/mav6b/Documents'
PYATS_TESTBED = 'pyATS/testbed.yaml'
LOCAL_DEVICE = '10.112.1.106'
CA_DIRECTORY = 'keys_and_certs'
CA_CERT_NAME = 'rootCA'

# Files to Build
SERVER_CSR_CONF = '''
[ req ]
default_bits = 4096
prompt = no
encrypt_key = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = US
ST = Ohio
L = Richfield
O = Cisco
OU = Federal
CN = mav6.ciscofederal.com

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = mav6
DNS.2 = mav6b
DNS.3 = mav6b.ciscofederal.com
IP.1 = 10.112.1.106
IP.2 = 2005:1117:1:1:5d09:21bf:60ea:42bb

'''

SERVER_CERT_CONF = '''
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = mav6.ciscofederal.com
DNS.2 = *.ciscofederal.com
DNS.3 = mav6b
DNS.4 = mav6b.ciscofederal.com
DNS.5 = server.ciscofederal.com
DNS.6 = server
IP.1 = 10.112.1.106
IP.2 = 2005:1117:1:1:5d09:21bf:60ea:42bb
'''