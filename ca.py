import os
import shutil
import random
from time import sleep
from OpenSSL import SSL, crypto

# pyATS
from pyats.topology import loader
from pyats.utils.fileutils import FileUtils
from genie.libs.sdk.apis.iosxe import utils
from genie.libs.sdk.apis.iosxe.ntp.configure import *



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
    

def ca_build_ca(ca_directory=''):
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


def ca_build_server_cert(csr_conf='', cert_conf='', server_name='', ca_directory=''):
    # This function builds a certificate for a server and stores it in the CA directory
    # csr_conf - server csr conf configuration lines to help bootstrap the csr
    # cert_conf - server cert conf configuration lines to help bootstrap the csr
    # server_name - hostname of the server being built, used to name the .key and .crt files (and conf file)
    # ca_directory - name of the CA directory

    #Build the server key
    os.chdir(ca_directory)
    command = 'openssl genrsa -out ' + server_name + '.key 4096'
    os.system(command)

    # Build CSR conf file and then the server CSR
    filename = server_name + '_csr.conf'
    with open(filename, 'w+') as f:
        f.writelines(csr_conf)
    sleep(2)

    command = 'openssl req -new -key ' + server_name + '.key -out ' + server_name + \
                '.csr -config ' + server_name + '_csr.conf'
    os.system(command)
    
    # Create the server certificate conf file,
    filename = server_name + '_cert.conf'
    with open(filename, 'w+') as f:
        f.writelines(cert_conf)
    sleep(2)

    # Create the server certificate
    command = 'openssl x509 -req -in ' + server_name + '.csr -CA rootCA.crt -CAkey rootCA.key ' + \
                '-CAcreateserial -out ' + server_name + '.crt -days 3650 -sha256 ' + \
                '-extfile ' + filename
    os.system(command)

    os.chdir('..')


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


def rtr_remove_tp(device=''):
    # THIS FUNCTION IS NOT CURRENTLY USED AND IS UNTESTED
    # This function removes the trustpoint from the router
    device.configure ('no crypto pki authenticate MAV6-TP\n' + 'yes\n' )


def rtr_authenticate_rootca(device='', ca_directory=''):
    # This function sends an exec command to the router to authenticate the rootCA.crt to the trustpoint
    # device - pyats device object
    # device - pyats device object to add the config to
    # ca_directory - directory of certificate authority 

    # Read the rootCA.crt file into a variable
    filename = os.path.join(ca_directory, 'rootCA.crt')
    with open(filename) as fileptr:
        rootCA = fileptr.read()

    # Remove the BEGIN CERT and END CERT lines, as the router does not expect them
    rootCA = rootCA.replace('-----BEGIN CERTIFICATE-----\n', '')
    rootCA = rootCA.replace('-----END CERTIFICATE-----\n', '\n\n')   

    # Execute the certificate authentication I dont know why it fails the first time, but suceeds the 2nd time
    try:
        device.api.configure_pki_authenticate_certificate(certificate=rootCA, 
                                                          label_name='MAV6-TP')
    except:
        sleep(4)
        device.api.configure_pki_authenticate_certificate(certificate=rootCA, 
                                                          label_name='MAV6-TP')
    sleep(2)


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
    new_cert.set_serial_number(1111)
    new_cert.gmtime_adj_notBefore(0)
    new_cert.gmtime_adj_notAfter(60*60*24*365*5)
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


def ca_create_key(ca_directory='', key_name=''):
    # THIS FUNCTION IS NOT IN USE RIGHT NOW
    # Init a new PKey object and generate a 4096 RSA key pair
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)

    # Read private and public keys into variables
    key_private = crypto.dump_privatekey(crypto.FILETYPE_PEM, key)
    key_public = crypto.dump_publickey(crypto.FILETYPE_PEM, key)

    # Write keys to ca_directory
    priv_key_name = key_name + '.key'
    pub_key_name = key_name + '-pub.key'
    with open(priv_key_name, 'w') as f:
        f.write(key_private)
    with open(pub_key_name, 'w') as f:
        f.write(key_public)


def ca_create_cert(ca_directory='', key_name=''):
    # This function assumes the rootCA.key and rootCA.crt exist in the directory
    # ca_directory - directory of certificate authority 
    # key_name - is the base filename of the existing key, i.e. 'server1' if key filename is server1.key
    #            it will also become the base filename for the new .crt file signed by the ca

    # Read rootCA.key and rootCA.crt and server public key into variables
    pub_key_name = key_name + '-pub.key'
    ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, 
                                    open(os.path.join(ca_directory, 'rootCA.key')).read())
    ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, 
                                      open(os.path.join(ca_directory, 'rootCA.crt')).read())
    key = crypto.load_publickey(crypto.FILETYPE_PEM,
                                open(os.path.join(ca_directory, pub_key_name)).read()) 

    # Build the certificate and add parameters
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
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(60*50*24*365*8)
    cert.set_issuer(ca_cert.get_subject())
    cert.set_pubkey(key)

    cert.add_extensions([
        crypto.X509Extension(b'subjectAltName', False,
            ','.join([
                'DNS:%s' % socket.gethostname(),
                'DNS:*.%s' % socket.gethostname(),
                'DNS:localhost',
                'DNS:*.localhost',
                'DNS:server',
                'DNS:server.ciscofederal.com',
                'IP:10.112.1.106',                
                ]).encode()),
        crypto.X509Extension(b"authorityKeyIdentifier", True, b"keyid,issuer"),
        crypto.X509Extension(b"basicConstraints", True, b"CA:false"),
        crypto.X509Extension(b"keyUsage", True, b"digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment"),
        ])
    cert.sign(ca_key, 'SHA256')

    # Write cert to ca_directory
    cert_filename = key_name + '.crt'
    with open(cert_filename, 'w') as f3:
        f3.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

