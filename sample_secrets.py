####### Test Device info ######
# TEST_DEVICE must be either an ipv4 address or an ipv6 address
# TEST_DEVICE_HOSTNAME must match the hostname of the test device
# TEST_DEVICE_OS must be iosxe or nxos, must match the pyats name for the os and device_pack filename
# CLI_USER and CLI_PASS must match the initial configuration of the test device, so other configs can be pushed
# Other parameters will be pushed through configs by mav6 before the test is run... in other words, 
# COM_RO (for example) will be pushed to the device through a config, then used by mav6 in contacting the device, 
# so use whatever name for it (and other parameters that works for you)
TEST_DEVICE = "10.1.1.1"
TEST_DEVICE = "2001:db8::1"
TEST_DEVICE_HOSTNAME = 'test_device'
TEST_DEVICE_OS = 'iosxe'
CLI_USER = "cli_username"
CLI_PASS = "cli_password"

AUTH_KEY = "some_password"
PRIV_KEY = "some_password"
SNMP_USER = "mav6user"
COM_RO = "snmp_ro"
COM_RW = "snmp_rw"

####### MAV6 Server INFO #######
# IPv4 and IPv6  address of the Mav6 server
# Note: Current release only supports Ubuntu
# MAV6_USER and MAV6_PASS are the sudo username and password
# NTP_TEST_SERVER is any NTP server the test_device can access
MAV6_IPV4 = "10.1.1.2"
MAV6_IPV6 = "2001:db8::2"
MAV6_USER = "mav6"
MAV6_PASS = "C1sco123!"
NTP_TEST_SERVER = "10.1.1.1"