[![Pylint](https://github.com/netfoundry/edge-router-registration/actions/workflows/pylint.yml/badge.svg)](https://github.com/netfoundry/edge-router-registration/actions/workflows/pylint.yml)

# edge-router-registration

NetFoundry registration script.

This script is made up of two parts.  

1. A bootstrap script - router_registration_bootstrap
1. The main registration script - router_registration

## Requirements

### OpenZiti Router auto enroll

The OpenZiti Regiration is a generic OpenZiti router registration script that can handle very custom configurations.  This script builds on top of that existing script.  In order to run this using python
you also need the ziti_router_auto_enroll.py in be in the same directory.  If using the binary build you
don't need the referenced file.

See the [ziti_router_auto_enroll](https://github.com/netfoundry/ziti_router_auto_enroll) source for more information.


## Bootstrap

The job of the bootstrap script is the download the latest version of the main script at run time, 
if the main doesn't exist or is older than 12hrs.

## Router Registration

The registration script is to provide an easy way for a end user to register the NetFoundry Edge Router using a OTP(one time password).

The registration process covers the following items: 

* Connects to NetFoundry to get information about the EdgeRouter using the OTP
* Checks connectivity to the controller
* Gathers information about the local machine & runs the ziti router enrollment
* Configures UFW rules to allow inbound ports based on configuration
* Configures a local salt-stack minion to work with NetFoundry
* Downloads the latest version of the [nfhelp menu](https://github.com/netfoundry/edge-router-nfhelp)


### Connect to NetFoundry
The script uses the OTP to reach out to NetFoundry & get information about the ER that's about to be
registered. The most important piece being the JWT for the ziti router.

### Connectivity Checks
Part of having a healty registration is ensuring the communication between the ER that's about to 
attempt registration & the controller.  This script will check if it's able to reach ports 80, 443 & 6262
on the controller.  If any of those ports are unreachable, then the registration will fail. 

In an attempt to verify connectivity this script will also check if the controller name returned from the OTP
matches the certificate when connecting to the controller.  If the reponse doesn't have the correct name within
the certificate, it most likey means there's a proxy is the mix & the registration might or might not succeed, but
the ziti router will for sure NOT function.

### Gather local info & run enrollment
Once the registration has information from NetFoundry it combines that with the local machine configuration to create
a command that will run the ziti_router_auto_enroll script(imported with python, not seperate binary).

NetFoundry enabled certain features by default:
  * Edge enabled: The edge portion of the router configuation is filled out with either local information or through input from the user.
  * Tunneler enabled: In order to run the edge-route in tunneler enabled modes, the OS needs to be configured to have the OpenZiti resolver as the first resolver.  This action requires a configuration be created for systemd-resolved. This configuration is depended on how the OS is configured, specifically what IP address is assigned & what interfaces exist.
  * HealthChecks enabled: The ctrlPingCheck health check is enabled & allows you to monitor the control plane connection to the controller.
  * proxyServices:  Builds two proxy services to allow the salt-stack minion commnunication.

### UFW Rules

The **default setting** for an ER is **NOT** going to advertise itself for inbound **fabric** connections, only **edge** connections.  
In this setting, the edge(443/tcp) is still allowed inbound, but only from the local subnet.

The NetFoundry console allows you to select if the ER is going to have "Link Listener".  

Enabling this setting makes the script attempt to lookup the external IP address & use it to advertise itself for other ERs in the fabric mesh to connect to it.  This implies the ER should be publicaly accessible with inbound FW rules open for the fabric(80/tcp) & edge(443/tcp) from anywere.

All NetFoundry Edge Router are configured with a local resolver(tunneler). So port 53/tcp & 53/udp are open from the local subnet.

HealthChecks are also enabled & listen so port 8081/tcp is open from the local subnet.

### Salt Minion configuration

NetFoundry uses salt-stack to push updates to EdgeRouters. The proxy connections are open on the local loopback & use ports 4505/tcp & 4506/tcp.

### NFhelp

Once the OpenZiti router registration & the salt-stack minions is configured, the script will download the latest version of the [nfhelp menu](https://github.com/netfoundry/edge-router-nfhelp)

### EBPF enabling

Ability to enable the [ebpf tproxy slicer](https://github.com/netfoundry/ebpf-tproxy-splicer) configuration.

## Usage

This script allows some options for the NetFoundry Edge-Router registration process. The available options include:

- An optional registration key
- An optional `--jwt` Path to file based jwt as an alternative to registration key

- An optional `-f/--force` flag to forcefully proceed with re-enrollment
- An optional `-l/--logLevel` argument to set the logging level (default: INFO)
- An optional `--logFile` argument to specify the log file (default: router_registration.log)
- An optional `--salt` flag to skip salt-stack setup
- An optional `--skip-fw` flag to skip applying firewall rules
- An optional `--skipChecks` flag t0 skip all controller checks
- An optional `--hostOnly` enable ER Tunnel in host mode & do not setup local dns
- An optional `--hostId` to specify a Salstack minion host id
- An optional `--downloadUrl` to specify an alternate bundle to download location
- An optional `--diverter` to enable diverter features
- An optional `--ntp` to specify an alternate ntp server to check the time
- An optional `--proxyType` to specify a proxy type
- An optional `--proxyAddress` to specify a proxy address
- An optional `--proxyPort` to specify a proxy port
- A `-v/--version` flag to display the current version of the tool

Additionally, the function allows for manual configuration of edge/fabric and tunnel components through the following arguments:

- `--edge`: IP or DNS name for the edge component
  - Will override the automatic detection of the default GW interface & take a hostname or IP address.  This information cannot be verified since it could be masked.
- `--tunnel_ip`: IP address for the tunnel component (if enabled)
  - Will override the automatic detection of the default GW interface & take an IP Address.  The IP must be assiged to one of the local interfaces, since this will listen for incoming traffic.
- `--fabric`: IP or DNS name for the fabric component (if enabled)
  - Will override the automatic detection of the default GW interface & take a hostname or IP address.  This information cannot be verified since it could be masked.
- `--dnsIPRange`:  Override the default resolver ip range assiged.
  - Must in in subnet notation.  Example: 100.64.0.0/10
- `--lanIf`: Override the interface name assigned to lanIf.
  - Will override the interface in which automatic firewall rules will be added to match services.  Must the name of the interface.
