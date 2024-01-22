import os
import inspect
import shutil
import random
from time import sleep
from OpenSSL import SSL, crypto

# pyATS
from pyats.topology import loader
from pyats.utils.fileutils import FileUtils
from genie.libs.sdk.apis.iosxe import utils
from genie.libs.sdk.apis.iosxe.pki.configure import *
from genie.libs.sdk.apis.iosxe.ntp.configure import *

from secrets import *
from test_configuration import *


def ca_create_directory(ca_directory = '', overwrite=True):
    # This function creates a new directory, but first, if overwrite is True it will delete the existing directory
    # ca_directory - the name of the directory to be created
    # overwrite - Will delete the directory name first if it already exists

    # If overwrite is true, delete the old directory if it exists
    if overwrite:
        if (os.path.isdir(ca_directory)):
            shutil.rmtree(ca_directory)
    # Make the new directory
    os.mkdir(ca_directory)
    

def ca_create_key(ca_directory='', key_name=''):
    # creates an RSA key pair and stores it in ca_directory
    # ca_directory - the directory to store the keys in
    # key_name - the base filename for the keys

    # Init a new PKey object and generate a 4096 RSA key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)

    # Read private and public keys into variables
    key_private = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    key_public = crypto.dump_publickey(crypto.FILETYPE_PEM, key)

    # Write keys to ca_directory
    os.chdir(ca_directory)
    priv_key_name = key_name + '.key'
    pub_key_name = key_name + '-pub.key'
    with open(priv_key_name, 'w') as f:
        f.write(key_private.decode())
    with open(pub_key_name, 'w') as f:
        f.write(key_public.decode())
    os.chdir('..')


def ca_create_cert(ca_directory='', key_name='', server_ip=''):
    # This function assumes the rootCA.key and rootCA.crt exist in the directory
    #     and build a cert signed by the rootCA.crt
    #     If key_name == 'rootCA', then this function will build rootCA.crt from rootCA.key
    # ca_directory - directory of certificate authority 
    # key_name - is the base filename of the existing key, i.e. 'server1' if key filename is server1.key
    #            it will also become the base filename for the new .crt file signed by the ca
    #            If key_name is rootCA, rootCA.crt will be built from the key in the directory
    #            and rootCA.fpt file will hold the fingerprint of the cert

    # Read rootCA.key and rootCA.crt and server public key into variables
    pub_key_name = key_name + '-pub.key'
    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, 
                                    open(os.path.join(ca_directory, 'rootCA.key')).read())
    ca_pub_key = crypto.load_publickey(crypto.FILETYPE_PEM, 
                                    open(os.path.join(ca_directory, 'rootCA-pub.key')).read())
    
    if (key_name != 'rootCA'): # building a server cert signed with ca key
        ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                          open(os.path.join(ca_directory, 'rootCA.crt')).read())
        server_pub_key = crypto.load_publickey(crypto.FILETYPE_PEM,
                                    open(os.path.join(ca_directory, pub_key_name)).read()) 
    else: # We are building the rootCA.crt, signed by rootCA.key (self-signed)
        server_pub_key = ca_pub_key

    # Instantiate the certificate object and add properties
    cert = crypto.X509()
    cert.get_subject().C = 'US'
    cert.get_subject().ST = 'Ohio'
    cert.get_subject().L = 'Richfield'
    cert.get_subject().O = 'Cisco'
    cert.get_subject().OU = 'Mav6'
    cert.get_subject().CN = key_name + '.mav6.lab'
    cert.get_subject().emailAddress = 'mav6@cisco.com'
    cert.set_serial_number(random.randrange(100000))
    cert.set_version(2)
    cert.gmtime_adj_notBefore(-(60*60*24*7))
    cert.gmtime_adj_notAfter(60*50*24*365*8)
    cert.set_pubkey(server_pub_key)
    if (key_name != 'rootCA'):
        cert.set_issuer(ca_cert.get_subject())
    else:
        cert.set_issuer(cert.get_subject())
    cert.add_extensions([
        crypto.X509Extension(b'subjectAltName', False,
            ','.join([
                #'DNS:%s' % socket.gethostname(),
                #'DNS:*.%s' % socket.gethostname(),
                'DNS:localhost',
                'DNS:*.localhost',
                ('DNS:' + key_name),
                ('DNS:' + key_name + '.ciscofederal.com'),
                ('IP:' + server_ip),                
                ]).encode()),
        #crypto.X509Extension(b"authorityKeyIdentifier", True, b"keyid,issuer"),
        crypto.X509Extension(b"basicConstraints", True, b"CA:false"),
        #crypto.X509Extension(b"keyUsage", True, b"digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment"),
        ])
    cert.sign(ca_key, 'SHA256')

    # Write cert to ca_directory
    os.chdir(ca_directory)
    cert_filename = key_name + '.crt'
    with open(cert_filename, 'w') as f3:
        f3.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode())

    # If we build the rootCA.crt get the fingerprint for it and save it to rootCA.fpt file
    if (key_name == 'rootCA'):
        # get fingerprint of rootCA.crt
        fingerprint = cert.digest('sha1').decode()
        fingerprint = fingerprint.replace(':', '')

        # Save the fingerprint to a file
        with open('rootCA.fpt', 'w+') as f:
            f.writelines(fingerprint)
    os.chdir('..')
    return cert

    
def rtr_remove_trustpoint(device=''):
    # This function removes the trustpoint from the router if it exists
    try:
        device.api.unconfigure_trustpoint(tp_name='MAV6-TP')
    except:
        # no trustpoint to remove
        pass


def rtr_add_trustpoint(device='', ca_directory=''):
    # This function adds the trustpoint configuration to the router, A trustpoint in Cisco's language is simply a pointer to a trusted CA
    # This function builds the configuration, but it must be completed by "authenticating" or importing the root certficicate
    # device - pyats device object to add the config to
    # ca_directory - directory of certificate authority 

    # Read thE rootCA cert's fingerprint into a variable
    filename = os.path.join(ca_directory, 'rootCA.fpt')
    with open(filename) as fileptr:
        fingerprint = fileptr.read()

    # send the trustpoint configuration to the router
    device.configure ('crypto pki trustpoint MAV6-TP\n' + \
                        'enrollment terminal\n' + \
                        'usage ssl-client\n' + \
                        'revocation-check none \n' + \
                        'fingerprint  ' + fingerprint + '\n'
                        )


def rtr_authenticate_rootca(device='', ca_directory=''):
    # This function sends an exec command to the router to authenticate the rootCA.crt to the trustpoint
    # device - pyats device object
    # device - pyats device object to add the config to
    # ca_directory - directory of certificate authority 

    # Read the rootCA.crt file into a variable
    filename = os.path.join(ca_directory, 'rootCA.crt')
    with open(filename) as fileptr:
        rootCA = fileptr.read()

    rootCA = rootCA.rstrip('\n')
    counter = 3
    cert_configured = False

    while(counter>0 and cert_configured == False):
        try:
            device.api.configure_pki_authenticate_certificate(certificate=rootCA, 
                                                            label_name='MAV6-TP')
        except:
            sleep(1)
            #tp_list = device.execute('show crypto pki trustpoint')
            counter -= 1
        else:
            sleep(2)
            cert_configured = True
    
    return cert_configured    
    
###########################

def rtr_build_csr(device=''):
    # NOT BEING USED RIGHT NOW    
    csr = device.api.configure_pki_enroll_certificate(label_name='MAV6-TP')
    substring_begin = "Certificate Request follows:\r\n\r\n"
    substring_end = '\r\n\r\n---End'
    csr = csr[(csr.find(substring_begin)+len(substring_begin)): csr.find(substring_end)]
    csr = '-----BEGIN CERTIFICATE REQUEST-----\n' + csr + \
            '\n-----END CERTIFICATE REQUEST-----\n'
    print(csr)
    return csr


def ca_sign_csr(csr='', hash='sha256'):
    # NOT BEING USED RIGHT NOW    
    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open('./keys_and_certs/rootCA.key').read())
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open('./keys_and_certs/rootCA.crt').read())
    csr_obj = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr)

    # Move info from CSR to new Certificate
    new_cert = crypto.X509()
    new_cert.set_issuer(ca_cert.get_subject())
    new_cert.set_pubkey(csr_obj.get_pubkey())
    new_cert.set_serial_number(random.randrange(100000))
    new_cert.gmtime_adj_notBefore(0)
    new_cert.gmtime_adj_notAfter(60*60*24*60)
    new_cert.sign(ca_key, 'sha256')

    return new_cert

def ca_sign_csr_cli(csr='', hash='sha256', test_device_cert_conf=''):
    # NOT BEING USED RIGHT NOW    
    os.chdir('keys_and_certs')
    with open('mgmt.csr', 'w+') as f:
        f.writelines(csr)
    with open('mgmt_cert.conf', 'w+') as f2:
        f2.writelines(test_device_cert_conf)
    sleep(2)

    command = 'openssl x509 -req -in mgmt.csr -CA rootCA.crt -CAkey rootCA.key ' + \
                '-CAcreateserial -out mgmt.crt -days 3650 -sha256 ' + \
                '-extfile mgmt_cert.conf'
    os.system(command)

    with open('mgmt.crt') as fileptr3:
        mgmt_cert = fileptr3.read()
    sleep(2)
    os.chdir('..')
    return mgmt_cert

def rtr_install_cert(device='', cert=''):
    # NOT BEING USED RIGHT NOW    
    device.api.crypto_pki_import(cert, label_name='MAV6-TP')


def ca_build_ca(ca_directory=''):
    # NO LONGER USED, SWAPPED IN PYOPENSSL BASED FUNCTION
    # This function builds a CA server by creating rootCA.key and rootCA.crt rootCA.fpt in the designated directory
    # ca_directory - relative path where to build the rootCA files

    os.chdir(ca_directory)
    command = 'openssl req -x509 -sha256 -days 3650 -nodes  -newkey rsa:4096 -subj ' + \
                '"/CN=mav6b.ciscofederal.com/C=US/L=Richfield/ST=Ohio"  -keyout rootCA.key -out rootCA.crt'
    os.system(command)

    # get fingerprint of rootCA.crt
    command = 'openssl x509 -in rootCA.crt -noout -fingerprint >> rootCA.fpt'
    os.system(command)
    with open('rootCA.fpt') as fileptr:
        fingerprint = fileptr.read()
    equal_position = fingerprint.rfind('=')
    fingerprint=fingerprint[equal_position+1:]
    fingerprint = fingerprint.replace(':', '')
    sleep(1)

    # Save the fingerprint to a file
    with open('rootCA.fpt', 'w+') as f:
        f.writelines(fingerprint)
    os.chdir('..')


