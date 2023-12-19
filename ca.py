import os
import shutil
from time import sleep
from OpenSSL import SSL, crypto

# pyATS
from pyats.topology import loader
from pyats.utils.fileutils import FileUtils
from genie.libs.sdk.apis.iosxe import utils
from genie.libs.sdk.apis.iosxe.ntp.configure import *



def ca_create_directory():
    # Delete old CA
    if (os.path.isdir('keys_and_certs')):
        shutil.rmtree('keys_and_certs')

    # Create the rootCA.key and rootCA.crt
    os.mkdir('keys_and_certs')
    

def ca_buildca(server_ip=''):
    # This function builds a CA server for the embedded https server certificates using openssl command line
    # FIrst it will create the rootCA.key and rootCA.crt, then use them to sign server.crt for the https server

    # Delete the old CA directory and files in it, if they exist
    if (os.path.isdir('keys_and_certs')):
        shutil.rmtree('keys_and_certs')

    # Create the rootCA.key and rootCA.crt
    os.mkdir('keys_and_certs')
    os.chdir('keys_and_certs')
    command = 'openssl req -x509 -sha256 -days 3650 -nodes  -newkey rsa:4096 -subj ' + \
                '"/CN=mav6b.ciscofederal.com/C=US/L=Richfield/ST=Ohio"  -keyout rootCA.key -out rootCA.crt'
    os.system(command)

    #Build the server CSR conf file and then the server CSR
    os.system('openssl genrsa -out server.key 4096')
    with open('server_csr.conf', 'w+') as f:
        f.writelines(SERVER_CSR_CONF)
    sleep(2)
    os.system('openssl req -new -key server.key -out server.csr -config server_csr.conf')
    # Create the server certificate conf file, then the server certificate
    with open('server_cert.conf', 'w+') as f:
        f.writelines(SERVER_CERT_CONF)

    sleep(2)
    command = 'openssl x509 -req -in server.csr -CA rootCA.crt -CAkey rootCA.key ' + \
                '-CAcreateserial -out server.crt -days 3650 -sha256 ' + \
                '-extfile server_cert.conf'
    os.system(command)

    # get fingerprint of server.crt
    # SHOULD THIS BE THE FINGERPRINT OF THE SERVER.CRT or ROOTCA.CRT?
    command = 'openssl x509 -in rootCA.crt -noout -fingerprint >> fingerprint.txt'
    os.system(command)
    with open('fingerprint.txt') as fileptr:
        fingerprint = fileptr.read()
    equal_position = fingerprint.rfind('=')
    fingerprint=fingerprint[equal_position+1:]
    fingerprint = fingerprint.replace(':', '')
    sleep(1)

    # Save the fingerprint to a file
    with open('fingerprint.txt', 'w+') as f:
        f.writelines(fingerprint)
    os.chdir('..')


def rtr_add_trustpoint(device=''):
    with open('keys_and_certs/fingerprint.txt') as fileptr:
        fingerprint = fileptr.read()

    device.configure ('crypto pki trustpoint MAV6-TP\n' + \
                        'enrollment terminal\n' + \
                        'revocation-check none \n' + \
                        'fingerprint  ' + fingerprint + '\n'
                        )


def rtr_authenticate_rootca(device=''):
    with open('keys_and_certs/rootCA.crt') as fileptr:
        rootCA = fileptr.read()
    '''
    device.configure ('crypto pki authenticate MAV6-TP\n' + \
                        rootCA + '\n\n' 
                        )
    '''
    # TAKE OUT BEGIN AND END LINES FIRST?
    rootCA = rootCA.replace('-----BEGIN CERTIFICATE-----\n', '')
    rootCA = rootCA.replace('-----END CERTIFICATE-----\n', '\n\n')    
    # dont know why it fails the first time, suceeds the 2nd time
    try:
        device.api.configure_pki_authenticate_certificate(certificate=rootCA, 
                                                          label_name='MAV6-TP')
    except:
        sleep(4)
        device.api.configure_pki_authenticate_certificate(certificate=rootCA, 
                                                          label_name='MAV6-TP')

    sleep(2)


def rtr_build_csr(device=''):
        csr = device.api.configure_pki_enroll_certificate(label_name='MAV6-TP')
        substring_begin = "Certificate Request follows:\r\n\r\n"
        substring_end = '\r\n\r\n---End'
        csr = csr[(csr.find(substring_begin)+len(substring_begin)): csr.find(substring_end)]
        csr = '-----BEGIN CERTIFICATE REQUEST-----\n' + csr + \
                '\n-----END CERTIFICATE REQUEST-----\n'
        print(csr)
        return csr


def ca_sign_csr(csr='', hash='sha256'):
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

def rtr_install_cert(device='', cert=''):
    device.api.crypto_pki_import(cert, label_name='MAV6-TP')


