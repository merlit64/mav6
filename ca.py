import os
import shutil
from time import sleep
from OpenSSL import SSL, crypto

# pyATS
from pyats.topology import loader
from pyats.utils.fileutils import FileUtils
from genie.libs.sdk.apis.iosxe import utils
from genie.libs.sdk.apis.iosxe.ntp.configure import *



def ca_create_directory(directory_name = ''):
    # Delete old CA
    if (os.path.isdir(directory_name)):
        shutil.rmtree(directory_name)

    # Create the rootCA.key and rootCA.crt
    os.mkdir(directory_name)
    

def ca_build_ca(server_ip='', directory_name=''):
    # This function builds a CA server for the embedded https server certificates using openssl command line
    # FIrst it will create the rootCA.key and rootCA.crt, then use them to sign server.crt for the https server

    os.chdir(directory_name)
    command = 'openssl req -x509 -sha256 -days 3650 -nodes  -newkey rsa:4096 -subj ' + \
                '"/CN=mav6b.ciscofederal.com/C=US/L=Richfield/ST=Ohio"  -keyout rootCA.key -out rootCA.crt'
    os.system(command)

    # get fingerprint of rootCA.crt
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


def ca_build_server(server_ip='', csr_conf='', cert_conf='', server_name='', directory_name=''):
    #Build the server CSR conf file and then the server CSR
    os.chdir(directory_name)
    command = 'openssl genrsa -out ' + server_name + '.key 4096'
    os.system(command)

    filename = server_name + '_csr.conf'
    with open(filename, 'w+') as f:
        f.writelines(csr_conf)
    sleep(2)

    command = 'openssl req -new -key ' + server_name + '.key -out ' + server_name + \
                '.csr -config ' + server_name + '_csr.conf'
    os.system(command)
    
    # Create the server certificate conf file, then the server certificate
    filename = server_name + '_cert.conf'
    with open(filename, 'w+') as f:
        f.writelines(cert_conf)

    sleep(2)
    command = 'openssl x509 -req -in ' + server_name + '.csr -CA rootCA.crt -CAkey rootCA.key ' + \
                '-CAcreateserial -out ' + server_name + '.crt -days 3650 -sha256 ' + \
                '-extfile ' + filename
    os.system(command)

    os.chdir('..')


def rtr_add_trustpoint(device='', directory_name=''):
    filename = os.path.join(directory_name, 'fingerprint.txt')
    with open(filename) as fileptr:
        fingerprint = fileptr.read()

    device.configure ('crypto pki trustpoint MAV6-TP\n' + \
                        'enrollment terminal\n' + \
                        'usage ssl-client\n' + \
                        'revocation-check none \n' + \
                        'fingerprint  ' + fingerprint + '\n'
                        )


def rtr_authenticate_rootca(device='', directory_name=''):
    filename = os.path.join(directory_name, 'rootCA.crt')
    with open(filename) as fileptr:
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


