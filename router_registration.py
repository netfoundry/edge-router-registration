#!/usr/bin/env python
"""
NetFoundry Edge Router Registration
"""
import argparse
import os
import sys
import socket
import logging
import json
import time
from datetime import datetime, timedelta
import ssl
import ipaddress
import subprocess
import platform
from urllib.parse import urlparse
import ntplib
import yaml
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from tqdm import tqdm
import psutil
import requests
from colorama import Fore, Style, init
import ziti_router_auto_enroll

def check_controller(controller_host):
    """
    Check controller for open ports & certificate. If anything doesn't work exit.

    :param controller_host (str): IP address or hostname of the controller host.
    """
    logging.info("Checking communication with controller")

    # check cert matches name
    check_controller_certificate(controller_host)

    # check controller for ports
    port_list = [443, 6262]
    for port in port_list:
        if not check_host_port(controller_host, port):
            logging.error("Unable to communicate with "
                          "controller using tcp port: %s", port)
            sys.exit(1)

def check_controller_certificate(controller_host):
    """
    Check if the controller's certificate matches the specified hostname.

    :param controller_host (str): IP address or hostname of the controller host.
    :return True if the controller's certificate matches the specified hostname,
            or IP address otherwise exit with an error.
    """
    logging.debug("Starting controller certificate check for host %s", controller_host)
    certificate = ssl.get_server_certificate((controller_host, 443)).encode('utf-8')
    loaded_cert = x509.load_pem_x509_certificate(certificate, default_backend())
    san = loaded_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    san_dns_names = san.value.get_values_for_type(x509.DNSName)
    cert_cn = loaded_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

    if controller_host in san_dns_names or controller_host in cert_cn:
        return True

    logging.error("Controller certificate doesn't match for host "
                  "'%s', Are you behind a proxy?", controller_host)
    sys.exit(1)

def check_registration_key(registration_key):
    """
    Check_environment_key determines the environment based on a registration key and
    return the MOP endpoint. If the key does not match exit.

    :param registration_key The registration key to check
    :return NetFoundry MOP endpoint
    """
    if len(registration_key) == 10:
        return 'https://gateway.production.netfoundry.io/core/v2/edge-routers'
    if len(registration_key) == 11:
        return 'https://gateway.production.netfoundry.io/core/v3/edge-router-registrations'
    if registration_key.startswith("SA"):
        key_environment = 'sandboox'
    if registration_key.startswith("ST"):
        key_environment = 'staging'
    if registration_key.startswith("DE"):
        key_environment = 'development'
    if len(registration_key) == 12:
        if key_environment == 'development':
            return 'http://localhost:9300/core/v2/edge-routers'
        return 'https://gateway.' + str(key_environment) + '.netfoundry.io/core/v2/edge-routers'
    if len(registration_key) == 13:
        if key_environment == 'development':
            return 'http://localhost:9300/core/v3/edge-router-registrations'
        return 'https://gateway.' + str(key_environment) + '.netfoundry.io/core/v3/edge-router-registrations'

    logging.error("Unable to determine environment using provided registration key")
    sys.exit(1)

def check_host_port(ip_host, port, max_retries=2, delay=1, timeout=2):
    """
    Check if a host is reachable on a specific port.

    :param ip_host: IP address or hostname of the host to check.
    :param port : Port number to check.
    :param max_retries (optional): Maximum number of retries to check the host. Defaults to 2.
    :param delay (optional): Delay in seconds between retries. Defaults to 1.
    :param timeout (optional): Timeout in seconds for the port check. Defaults to 2.

    :return True if the host is reachable on the specified port, False otherwise.
    """
    logging.debug("Starting hostcheck for host/port %s/%s", ip_host, port)

    for _ in range(max_retries):
        if check_port(ip_host, port, timeout):
            return True
        time.sleep(delay)
    return False

def check_port(ip_host, port, timeout):
    """
    Check if a host is reachable on a specific port.

    :param ip_host (str): IP address or hostname of the host to check.
    :param port (int): Port number to check.
    :param timeout (int): Timeout in seconds for the port check.

    :return True if the host is reachable on the specified port, False otherwise.
    """
    bypass = os.environ.get('NF_PORT_BYPASS')
    logging.debug("Bypass value: %s", bypass)
    if bypass:
        bypass = int(os.environ.get('NF_PORT_BYPASS'))
    else:
        bypass = 0
    if bypass == port:
        logging.info("Bypassing port check for port: %s", bypass)
        return True
    socket_connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socket_connection.settimeout(timeout)
    try:
        socket_connection.connect((ip_host, int(port)))
        socket_connection.shutdown(socket.SHUT_RDWR)
        return True
    except socket.error as error:
        if port == 6262:
            logging.info("Found port 6262 closed - could be intentional")
            return True
        else:
            logging.error("Socket error: %s", error)
            return False
    finally:
        socket_connection.close()

def check_root_permissions():
    """
    Check to see if this is running as root privileges & exit if not.

    """
    if os.geteuid() >= 1:
        logging.error("This script must be run with elevated privileges, "
                      "please use sudo or run as root")
        sys.exit(1)

def check_ipv4_interface_count(parser):
    """
    Check the number of IPv4 network interfaces on the local machine,
    excluding the loopback interface. Exits the program with an error message
    if more than one interface is found.

    :param parser: The argparse.ArgumentParser instance to add the arguments to.
    """
    network_interfaces = psutil.net_if_addrs()
    ipv4_interfaces = 0

    for interface, addrs in network_interfaces.items():
        if interface == "lo":
            continue
        for addr in addrs:
            if addr.family == socket.AF_INET:
                ipv4_interfaces += 1
                break
    logging.debug("Found %s interface(s)", ipv4_interfaces)
    if ipv4_interfaces > 1:
        logging.error("Found more than one network interface/IP address."
                      " Please use the flags -e/b and -i for manual configuration")
        parser.print_help()
        sys.exit(1)

def check_subnet(subnet_str):
    """
    Check if the provided subnet string is a valid subnet.

    Arguments:
    subnet_str -- A string representing the subnet in the format 'ip_address/prefix_length'.

    Returns:
    True if the subnet is valid and conforms to the criteria, False otherwise.
    """
    logging.debug("Checking subnet")
    if not "/" in subnet_str:
        logging.error("Subnet is not in slash notation")
        sys.exit(1)
    if "/32" in subnet_str:
        logging.error("Unable to support /32 subnets")
        sys.exit(1)
    try:
        subnet = ipaddress.ip_network(subnet_str)
        logging.debug(subnet)
        return subnet.prefixlen < subnet.max_prefixlen and subnet.prefixlen > 0
    except (ValueError, AttributeError):
        logging.error("Unable to parser subnet")
        sys.exit(1)

def check_time_diff(margin_minutes=10, server="pool.ntp.org"):
    """
    Check if the local time is within a specified margin from the NTP server.

    :param margin_minutes: The acceptable margin in minutes. Default is 5 minutes.
    :param server: The NTP server address. Default is "pool.ntp.org".
    return: True if local time is within the acceptable margin from the NTP server
    """
    ntp_time = None
    # Get the current NTP time
    try:
        client = ntplib.NTPClient()
        response = client.request(server)
        ntp_time = datetime.utcfromtimestamp(response.tx_time)
    except ntplib.NTPException:
        logging.warning("Unable to compare time.")

    if ntp_time:
        logging.debug("ntp time: %s", ntp_time)
        # Get the local time
        local_time = datetime.now()
        logging.debug("local time: %s", local_time)

        # Calculate the difference between local time and NTP time
        time_difference = local_time - ntp_time
        logging.debug("Time difference: %s", time_difference)

        # Check if the absolute difference is within the specified margin
        if abs(time_difference) >= timedelta(minutes=margin_minutes):
            logging.error("Time difference: %s", time_difference)
            logging.error("Unable to proceed, please check local time")
            sys.exit(1)

def create_netfoundry_tuning_file():
    """
    Creates a file named '01-netfoundry_tuning.conf' containing specific tuning content
    in the '/etc/sysctl.d/' directory, and then issues the 'sysctl --system' command.

    """
    logging.info("Tunning Network parameters via sysctl")
    tuning_content = ("# Netfoundry\n"
                      "# Adjustment for tcp stack\n"
                      "net.core.rmem_max = 16777216\n"
                      "net.core.wmem_max = 16777216\n"
                      "net.core.rmem_default = 16777216\n"
                      "net.core.wmem_default = 16777216\n"
                      "net.ipv4.tcp_rmem = 4096 87380 16777216\n"
                      "net.ipv4.tcp_wmem = 4096 65536 16777216\n"
                      "net.ipv4.tcp_mem = 8388608 8388608 16777216\n"
                      "net.ipv4.udp_mem = 8388608 8388608 16777216\n"
                      "net.ipv4.tcp_retries2 = 8\n")

    file_name = "01-netfoundry_tuning.conf"
    file_path = "/etc/sysctl.d/"

    with open(os.path.join(file_path, file_name), "w", encoding='UTF-8') as open_file:
        open_file.write(tuning_content)

    try:
        subprocess.run(["sysctl", "--system"],
                       check=True,
                       capture_output=True,
                       text=True,
                       timeout=15)
    except subprocess.CalledProcessError as error:
        logging.error("Unable to sysctl: %s", error)

def create_parser():
    """
    Create argparser Namespace

    :return: A Namespace containing arguments
    """
    __version__ = '1.4.0'
    parser = argparse.ArgumentParser()

    mgroup = parser.add_mutually_exclusive_group(required=True)

    mgroup.add_argument('registration_key', nargs='?',
                        help='NetFoundry Edge-Router Registration Key')
    mgroup.add_argument('--jwt', type=str,
                        help='Path to file based jwt')
    parser.add_argument('-f', '--force',
                        action="store_false",
                        help='Forcefully proceed with re-enrollment',
                        default=True)
    parser.add_argument('-l', '--logLevel', type=str,
                        choices=['DEBUG', 'INFO', 'ERROR'],
                        default='INFO',
                        help='Set the logging level - Default: INFO)')
    parser.add_argument('--logFile', type=str,
                        help='Specify the log file -'
                             'Default router_registration.log',
                        default='/var/log/router_registration.log')
    parser.add_argument('-s', '--salt',
                        action="store_false",
                        help='Skip salt-stack setup',
                        default=True)
    parser.add_argument('-w','--skip-fw',
                        action='store_false',
                        help='Skip applying fw rules',
                        default=True)
    parser.add_argument('--hostOnly',
                        action='store_true',
                        help='Enable ER Tunnel in host mode & do not setup local dns',
                        default=False)
    parser.add_argument('--hostId', type=str,
                        help='Salstack minion host id')
    parser.add_argument('--linkListener',
                        action='store_false',
                        help='Enabled local LinkListener')
    parser.add_argument('--downloadUrl', type=str,
                        help='Specify bundle to download')
    parser.add_argument('--ntp', type=str,
                        help='Specify ntp server to check',
                        default="pool.ntp.org")
    parser.add_argument('--diverter',
                        action='store_true',
                        help='Enable diverter',
                        default=False)
    parser.add_argument('--proxyType',type=str,
                        help='Proxy type')
    parser.add_argument('--proxyAddress',type=str,
                        help='Proxy Address')
    parser.add_argument('--proxyPort',type=int,
                        help='Proxy Port')
    parser.add_argument('--customRepoAddress',type=str,
                        help="Override the default github repository address"
                             " - replacement must match github structure")

    parser.add_argument('-v', '--version',
                        action='version',
                        version=__version__)

    group = parser.add_argument_group('Manual Configuration',
                                      'Manually configure edge/fabric and tunnel')
    group.add_argument('-e', '--edge',
                       help='IP or DNS name for edge component')
    group.add_argument('-i', '--tunnel_ip',
                       help="IP Address for tunnel component(if enabled)")
    group.add_argument('-b', '--fabric',
                       help='IP or DNS name for fabric component(if enabled)')
    group.add_argument('--dnsIPRange',
                       help='Override the default resolver ip range assiged. '
                       'Must in in subnet notation 100.64.0.0/10')
    group.add_argument('--lanIf',
                       help='Override the interface name assigned to lanIf.')

    return parser

def diverter_add():
    """
    Download, install & initialize setup of the diverter(zfw)

    """
    logging.info("Fetching latest diverter")
    try:
        release_response = requests.get("https://api.github.com/repos"
                                        "/netfoundry/zfw/releases/latest",
                                        timeout=15)
        release_data = release_response.json()
    except requests.exceptions.ConnectionError as exception_result:
        logging.warning('An issue occurred while trying to connect: %s', exception_result)

    if platform.machine() in ['x86_64','AMD64']:
        system_arch = 'amd64'

    package_filename = f"zfw-tunnel_{release_data['tag_name']}_{system_arch}.deb"

    download_url = None
    for asset in release_data["assets"]:
        if system_arch in asset["name"]:
            download_url = asset["browser_download_url"]
            break

    if download_url is None:
        logging.error("No matching package %s found", package_filename)
        sys.exit(1)

    try:
        response = requests.get(download_url, stream=True, timeout=60)

        total_size = int(response.headers.get("content-length", 0))
        block_size = 1024  # 1 Kibibyte
        status_bar = tqdm(total=total_size, unit="iB", unit_scale=True, desc="Downloading")

        with open(package_filename, "wb") as open_file:
            for data in response.iter_content(block_size):
                status_bar.update(len(data))
                open_file.write(data)

        status_bar.close()
    except requests.exceptions.ConnectionError as exception_result:
        logging.warning('An issue occurred while trying to connect: %s', exception_result)
    except requests.exceptions.Timeout as timeout_exception:
        logging.warning('Timed out trying to download diverter %s', timeout_exception)

    logging.info("Installing diverter package")
    try:
        subprocess.run([f"sudo dpkg -i {package_filename}"], shell=True, check=True)
        os.remove(package_filename)
    except subprocess.CalledProcessError as error:
        logging.warning("Unable to run diverter install: %s", error)

    logging.info("Running diverter setup")
    try:
        subprocess.run(["/opt/openziti/bin/start_ebpf_router.py"],
                       check=True)
    except subprocess.CalledProcessError as error:
        logging.warning("Unable to run diverter setup: %s", error)

def diverter_remove():
    """
    Revert & cleanup an existing instance of diverter
    """
    if os.path.isfile("/opt/openziti/bin/revert_ebpf_router.py"):
        logging.info("Cleaning up diverter")
        try:
            subprocess.run(["/opt/openziti/bin/revert_ebpf_router.py"],
                        check=True)
        except subprocess.CalledProcessError as error:
            logging.warning("Unable to run diverter cleanup: %s", error)

def get_interface_by_ip(ip_address):
    """
    Get the name of the network interface that the given IP address belongs to.

    :param ip_address: A string representing the IP address to look up.
    :return: The name of the network interface that the IP address belongs to, or None if not found.
    """
    try:
        ip_addr = ipaddress.ip_address(ip_address)
    except ValueError:
        logging.error("Invalid IP address: %s", ip_address)

    network_interfaces = psutil.net_if_addrs()

    for interface, addrs in network_interfaces.items():
        for addr in addrs:
            if addr.family == socket.AF_INET and ip_addr == ipaddress.ip_address(addr.address):
                return interface

    logging.error("Unable to find interface name for ip.")
    sys.exit(1)

def get_mop_router_information(endpoint_url, registration_key):
    """
    Retrieve MOP router information from the given endpoint URL and registration key and
    return the json results. If the jwt is None exit.

    :param endpoint_url: The URL of the endpoint where MOP router information is located.
    :param registration_key: The registration key for accessing the MOP router information.
    :return: The response object containing MOP router information.
    """
    try:
        headers = {'content-type': 'application/json'}
        endpoint_url = f"{endpoint_url}/register/{registration_key}"
        logging.debug("Connecting to: %s", endpoint_url)
        response = requests.post(endpoint_url,
                                 headers=headers,
                                 timeout=20)
        http_code = response.status_code
        logging.debug('HTTP Response STATUS CODE: %s', http_code)
    except requests.exceptions.ConnectionError as exception_result:
        logging.error('An issue occurred while trying to connect: %s', exception_result)
        sys.exit(1)
    except requests.exceptions.Timeout as timeout_exception:
        logging.error('Timed out trying to reach MOP: %s', timeout_exception)
        sys.exit(1)
    if response.status_code == 200:
        if json.loads(response.text)['edgeRouter']['jwt'] is None:
            logging.error("Registration with this key has already been performed")
            sys.exit(1)
        return json.loads(response.text)
    if response.status_code == 400:
        logging.error("Unable to verify key, response: %s", response.text)
        sys.exit(1)
    else:
        logging.error("Failed to reach NetFoundry: %s", http_code)
        sys.exit(1)

def get_subnet_by_ip(input_ip):
    """
    Given an IP address, this function checks local interfaces to determine
    the network subnet the IP address belongs to and returns the base network
    with the subnet in slash notation.

    :param ip: IPv4 address as a string.
    :return: Base network with subnet in slash notation, or None if no subnet is found.
    """
    # Convert input IP address to IPv4Address object
    input_ip = ipaddress.IPv4Address(input_ip)

    # Iterate over local network interfaces
    for interface in psutil.net_if_addrs().values():
        for addr in interface:
            # Check if the address is IPv4
            if addr.family == socket.AF_INET:
                ip_address = ipaddress.IPv4Address(addr.address)
                netmask = ipaddress.IPv4Address(addr.netmask)

                # Create a network object using the IP and netmask
                network = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)

                # Check if input IP is within the current network subnet
                if input_ip in network:
                    return str(network)

    logging.error("Unable to determin subnet for: %s", input_ip)
    sys.exit(1)

def handle_ufw_rules(args, router_info, ufw_save_file):
    """
    Handle the creation and updating of Uncomplicated Firewall (ufw) rules based on provided
    arguments, router information, and save the rules to a specified file. This function will
    retrieve the local IP and subnet information. Add a rule for health checks to the local
    subnet on port 8081 (TCP). Add DNS rules (port 53, both TCP and UDP) to the local or
    tunnel subnet depending on the presence of a tunnel IP argument. Add rules for edge router
    link listeners on ports 80 and 443 (TCP) or only port 443 (TCP) to the local subnet.

    :param args (argparse.Namespace): A Namespace object containing the parsed arguments.
    :param router_info (dict): A dictionary of router information returned by NetFoundry
    :param ufw_save_file(str): The file path where the ufw rules will be saved.
    """
    # get local ip/subnet info
    local_ip = ziti_router_auto_enroll.get_private_address()
    local_subnet = get_subnet_by_ip(local_ip)

    # add tunnler DNS and HealthChecks rules
    if args.tunnel_ip:
        # lookup local interface
        tunnel_ip = args.tunnel_ip
        tunnel_subnet = get_subnet_by_ip(tunnel_ip)
        ufw_add_rules(tunnel_subnet, '53', 'udp', ufw_save_file)
        ufw_add_rules(tunnel_subnet, '53', 'tcp', ufw_save_file)
        ufw_add_rules(tunnel_subnet, '8081', 'tcp', ufw_save_file)
    else:
        # lookup local interface
        local_ip = ziti_router_auto_enroll.get_private_address()
        local_subnet = get_subnet_by_ip(local_ip)
        ufw_add_rules(local_subnet, '53','udp', ufw_save_file)
        ufw_add_rules(local_subnet, '53','tcp', ufw_save_file)
        ufw_add_rules(local_subnet, '8081', 'tcp', ufw_save_file)

    if router_info['edgeRouter']['linkListener']:
        ufw_add_rules('0.0.0.0/0','80', 'tcp', ufw_save_file)
        ufw_add_rules('0.0.0.0/0','443', 'tcp', ufw_save_file)
    else:
        ufw_add_rules(local_subnet, '443', 'tcp', ufw_save_file)

def handle_ziti_router_auto_enroll(args, router_info, enrollment_commands):
    """
    Handles the gathering information & running of the ziti_router_auto_enroll.

    :param args (argparse.Namespace): A Namespace object containing the parsed arguments.
    :param router_info (dict): A dictionary of router information returned by NetFoundry
    :param enrollment_commands(list): A list of commands to pass in the enrollment
    """
    # set install dir
    enrollment_commands.append('--installDir')
    enrollment_commands.append('/opt/netfoundry/ziti/ziti-router')

    # add tunneler by default for NetFoundry edge-router customers
    # if overriding the tunnel ip, check if valid and configure a
    # manual tunnelListener.  Otherwise just let the auto_enroller
    # create one.

    if args.hostOnly:
        enrollment_commands.append("--skipDNS")
        enrollment_commands.append("--tunnelListener")
        enrollment_commands.append("host")
    elif args.tunnel_ip or args.lanIf or args.dnsIPRange:
        if args.lanIf:
            interface_name = args.lanIf
        if args.tunnel_ip:
            tunnel_ip = args.tunnel_ip
            if not args.lanIf:
                interface_name = get_interface_by_ip(tunnel_ip)
        else:
            tunnel_ip = ziti_router_auto_enroll.get_private_address()
            if not args.lanIf:
                interface_name = get_interface_by_ip(tunnel_ip)
        if args.dnsIPRange:
            dns_ip_range = args.dnsIPRange
        else:
            dns_ip_range = '100.64.0.0/10'
        enrollment_commands.append("--tunnelListener")
        enrollment_commands.append("tproxy")
        enrollment_commands.append(f"udp://{tunnel_ip}:53")
        enrollment_commands.append(f"{interface_name}")
        enrollment_commands.append(dns_ip_range)
    else:
        enrollment_commands.append('--autoTunnelListener')

    # if overriding the edge listener add a manual edgeListner
    # Otherwise the auto_enroller will create one by default.
    if args.edge:
        enrollment_commands.append('--edgeListener')
        enrollment_commands.append('tls:0.0.0.0:443')
        enrollment_commands.append(f"{args.edge}:443")

    # if the setting was selected in the NetFoundry console
    # if overriding the fabric listener add a manual linkListener
    # Otherwise the auto_enroller will create one if passing in
    # --assumePublic.
    if router_info['edgeRouter']['linkListener']:
        if args.fabric:
            enrollment_commands.append('--linkListeners')
            enrollment_commands.append('transport')
            enrollment_commands.append('tls:0.0.0.0:80')
            enrollment_commands.append(f"tls:{args.fabric}:80")
        else:
            enrollment_commands.append('--assumePublic')

    # add jwt to enrollment command that was retrieved from NetFoundry
    # insert it as the first argument to ensure the positional
    enrollment_commands.insert(0, router_info['edgeRouter']['jwt'])

    # add proxyListners for salt-stack
    enrollment_commands.append('--proxyListeners')
    enrollment_commands.append('tcp:127.0.0.1:4505')
    enrollment_commands.append('salt4505')
    enrollment_commands.append('--proxyListeners')
    enrollment_commands.append('tcp:127.0.0.1:4506')
    enrollment_commands.append('salt4506')

    # download the bundle from whatever link NetFoundry sets
    enrollment_commands.append('--downloadUrl')
    if args.downloadUrl:
        enrollment_commands.append(args.downloadUrl)

    elif args.customRepoAddress:
        logging.info("Downloading from custom repo")
        enrollment_commands.append(f"https://{args.customRepoAddress}/openziti/ziti/"
                "releases/download/v{router_info['productMetadata']['zitiVersion']}/"
                "ziti-linux-amd64-{router_info['productMetadata']['zitiVersion']}.tar.gz")
    else:
        enrollment_commands.append(router_info['productMetadata']['zitiBinaryBundleLinuxAMD64'])


    # check if ziti version is 0.30.0 or above
    fabric_port = ziti_router_auto_enroll.compare_semver(
        router_info['productMetadata']['zitiVersion'],'0.30.0'
    )

    # pass in fabric port 443 for versions 0.30.0 and above
    if fabric_port >= 0:
        logging.debug("Setting fabric port to 443")
        enrollment_commands.append('--controllerFabricPort')
        enrollment_commands.append('443')

    # add proxy if specified
    if args.proxyAddress:
        enrollment_commands.append('--proxyAddress')
        enrollment_commands.append(args.proxyAddress)
        if args.proxyType:
            enrollment_commands.append('--proxyType')
            enrollment_commands.append(args.proxyType)
        if args.proxyPort:
            enrollment_commands.append('--proxyPort')
            enrollment_commands.append(str(args.proxyPort))

    # print enrollment command in debug
    logging.debug(enrollment_commands)

    # run enrollment
    ziti_router_auto_enroll.main(enrollment_commands)

    # for backward compatability with existing NetFoundry deployments
    target = "/opt/netfoundry/ziti/ziti-router/ziti"
    source = "/opt/netfoundry/ziti/ziti"
    os.rename(target, source)
    os.symlink(source, target)

def process_manual_registration_arguments(args):
    """
    a
    """
    if not args.downloadUrl:
        logging.error("--downloadUrl is required when using --jwt")
        sys.exit(1)
    if not args.hostId:
        logging.error("--hostId is required when using --jwt")
        sys.exit(1)
    jwt_info, jwt_string = ziti_router_auto_enroll.decode_jwt(args.jwt)
    router_info={}
    router_info['networkControllerHost'] = urlparse(jwt_info['iss']).hostname
    router_info['edgeRouter']={}
    router_info['edgeRouter']['jwt'] = jwt_string
    router_info['edgeRouter']['hostId'] = args.hostId
    if args.linkListener:
        router_info['edgeRouter']['linkListener'] = True

    router_info['productMetadata']={}
    ziti_version = ziti_router_auto_enroll.get_ziti_controller_version(jwt_info['iss'])
    router_info['productMetadata']['zitiVersion'] = ziti_version

    return router_info

def salt_stack_add(router_info):
    """
    Creates a salt-stack minion configuration & starts the salt-minion process.
    Runs the command "salt-call state.apply" which applies the salt high-state.

    :param router_info (dict): A dictionary of router information returned by NetFoundry
    """
    logging.info("Creating Salt configuration")
    minion_config = '/etc/salt/minion.d/nf-minion.conf'
    yaml_content = ({'id': router_info['edgeRouter']['hostId'],
                     'master': '127.0.0.1',
                     'grains': {'roles': ['ER']}})
    try:
        with open(minion_config, "w", encoding='UTF-8') as open_file:
            yaml.dump(yaml_content, open_file, sort_keys=False)
    except OSError:
        logging.error("Unable to create salt minion config file")

    ziti_router_auto_enroll.manage_systemd_service('salt-minion', 'start')
    ziti_router_auto_enroll.manage_systemd_service('salt-minion', 'enable')
    logging.info("Applying Salt Minion State, this might take a minute...")
    try:
        subprocess.run(['salt-call','state.apply'],
                       check=True,
                       capture_output=True,
                       text=True,
                       timeout=300)
    except subprocess.CalledProcessError as error:
        logging.error(error)
        logging.error("Unable to apply salt-configuration, is Ziti funtional?"
                      "Please check the ziti logs to confirm")

def salt_stack_remove():
    """
    Stops the salt-minion service and removes the configuration files
    if a NetFoundry config is found.
    """
    nf_minion_config = "/etc/salt/minion.d/nf-minion.conf"

    if os.path.isfile(nf_minion_config):
        ziti_router_auto_enroll.manage_systemd_service('salt-minion', 'stop')

        files_to_remove = [
            "/etc/salt/pki/minion/minion_master.pub",
            "/etc/salt/pki/minion/minion.pub",
            "/etc/salt/pki/minion/minion.pem",
            nf_minion_config
        ]

        logging.info("Removing previous salt-stack minion configuration")

        for config_file in files_to_remove:
            if os.path.isfile(config_file):
                try:
                    os.remove(config_file)
                except OSError:
                    logging.error("Unable to remove %s", config_file)
                    sys.exit(1)

def setup_logging(logfile, loglevel=logging.INFO):
    """
    Set up logging to log messages to both the console and a file.

    :param logfile: The file to log messages to. Defaults to 'program_name.log'.
    :param loglevel: The minimum level of log messages to display. Defaults to logging.INFO.
    """
    class CustomFormatter(logging.Formatter):
        """
        Return a custom color for the message if the level is higher than warning.
        """
        def format(self, record):
            if record.levelno == logging.DEBUG:
                level_color = Fore.MAGENTA
            elif record.levelno == logging.WARNING:
                level_color = Fore.YELLOW
            elif record.levelno >= logging.ERROR:
                level_color = Fore.RED
            else:
                level_color = ""

            formatted_msg = super().format(record)
            colored_levelname = f"{level_color}{record.levelname}{Style.RESET_ALL}"
            return formatted_msg.replace(record.levelname, colored_levelname)
    def console_format(record):
        if record.levelno == logging.INFO:
            return console_formatter_info.format(record)
        return console_formatter_warning_error.format(record)

    # Initialize colorama
    init(autoreset=True)

    # Create a logger object
    logger = logging.getLogger()
    logger.setLevel(loglevel)

    # Create a file handler to log messages to a file
    file_handler = logging.FileHandler(logfile)
    file_handler.setLevel(loglevel)

    # Create a console handler to log messages to the console
    console_handler = logging.StreamHandler()
    console_handler.setLevel(loglevel)

    # Create formatters with custom date and time format, add them to the appropriate handlers
    file_formatter = CustomFormatter('%(asctime)s-%(levelname)s-%(message)s',
                                    datefmt='%Y-%m-%d-%H:%M:%S')

    file_handler.setFormatter(file_formatter)

    console_formatter_info = CustomFormatter('%(message)s')
    console_formatter_warning_error = CustomFormatter('%(levelname)s-%(message)s')

    console_handler.format = console_format

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

def ufw_add_rules(network_address, port, protocol, ufw_save_file):
    """
    Add Uncomplicated Firewall (UFW) rules for a specified source and save them in a file.

    :param network_address: The network address the rules should be created.
    :param port (str): The port number to allow inbound traffic.
    :param protocol (str): The protocol for which to allow inbound traffic (e.g., 'tcp', 'udp').
    :param source (str): The source of the traffic to be allowed, either 'local' or 'any'.
    """
    logging.info("Adding firewall rule to allow inbound %s from %s",
                    port,
                    network_address)
    logging.debug("Running command: ufw allow from %s to any port %s proto %s",
                    network_address,
                    port,
                    protocol)

    cmd = ["ufw", "allow", "from",
            network_address,
            "to", "any", "port",
            port,
            "proto",
            protocol]
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError:
        logging.error("Unable to run command: %s", cmd)

    try:
        with open(ufw_save_file, "a", encoding='UTF-8') as open_file:
            open_file.write(f"from {network_address} to any port {port} proto {protocol}\n")
    except FileNotFoundError:
        logging.error("Unable to write to file: %s", ufw_save_file)

def ufw_remove_rules(ufw_save_file):
    """
    Remove UFW rules stored in the rules file.

    :param ufw_save_file(path): The path to the ufw save file.
    """

    if not os.path.exists(ufw_save_file):
        logging.debug("Rules file %s does not exist. No rules to remove.", ufw_save_file)
        return

    try:
        with open(ufw_save_file, "r", encoding='UTF-8') as open_file:
            rules = open_file.readlines()
    except FileNotFoundError:
        logging.error("Unable to read file: %s", ufw_save_file)
        return

    for rule in rules:
        logging.info("Removing firewall rule: %s", rule.strip())
        logging.debug("Running command: ufw delete allow %s", rule.strip())

        cmd = ["ufw", "delete", "allow"] + rule.strip().split()
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError:
            logging.error("Unable to run command: %s", cmd)

    # Clear the rules file
    try:
        os.remove(ufw_save_file)
    except OSError:
        logging.error("Unable to remove previous ufw rules file")

def main():
    """
    Main logic
    """
    # create parser
    parser = create_parser()

    # get arguments passed
    args = parser.parse_args()

    # root check
    check_root_permissions()

    # start the ziti_router_auto_enroll command list
    enrollment_commands=[]

    # set log file name
    if args.logFile:
        log_file = args.logFile

    else:
        program_name = (os.path.basename(__file__)).split(".")[0]
        log_file = f"{program_name}.log"

    # setup logging
    setup_logging(log_file, args.logLevel)


    logging.info("\033[0;35mStarting Registration\033[0m")

    # check time
    check_time_diff(server=args.ntp)

    # check the number of interfaces
    if not args.edge:
        check_ipv4_interface_count(parser)

    # check subnet if passed
    if args.dnsIPRange:
        check_subnet(args.dnsIPRange)

    # set the ufw_save file used to track ufw rules created
    ufw_save_file='/opt/netfoundry/ziti/ziti-router/ufw_save_file.txt'

    # check if already registered
    if args.force:
        if os.path.isfile("/opt/netfoundry/ziti/ziti-router/.is_registered"):
            logging.error("Already registered. Override with -f/--force")
            sys.exit(1)
    else:
        enrollment_commands.append('-f')
        logging.info("Forcing re-registration, running cleanup first")
        ufw_remove_rules(ufw_save_file)
        salt_stack_remove()
        diverter_remove()
        if os.path.exists("/opt/netfoundry/ziti/ziti-router/ziti"):
            os.remove("/opt/netfoundry/ziti/ziti-router/ziti")

    # os tunning
    create_netfoundry_tuning_file()

    # set mop endpoint using the registration key
    if args.registration_key:
        mop_endpoint = check_registration_key(args.registration_key)

        # get jwt from MOP
        router_info = get_mop_router_information(mop_endpoint, args.registration_key)
        logging.debug(router_info)
    else:
        router_info = process_manual_registration_arguments(args)

    # check controller communications
    if not args.proxyAddress:
        check_controller(router_info['networkControllerHost'])

    # handle ziti_router_auto_enroll
    handle_ziti_router_auto_enroll(args, router_info, enrollment_commands)

    # setup UFW
    if args.skip_fw:
        handle_ufw_rules(args, router_info, ufw_save_file)

    # setup salt
    if args.salt:
        salt_stack_add(router_info)

    # enable diverter
    if args.diverter:
        diverter_add()


    logging.info("\033[0;35mRegistration Successful\033[0m")
    logging.info("\033[0;35mPlease use\033[0m \033[0;31mnfhelp-update\033[0;35m "
                 "before you use nfhelp commands\033[0m")

# main
if __name__ == '__main__':
    main()
