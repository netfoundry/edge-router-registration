# Ziti Router Auto Enroll

This Python script automates the process of enrolling and configuring a Ziti edge router. The script takes care of generating the configuration file, handling the enrollment process, and setting up DNS settings.

## Requirements

### Running compiled binary
- Ubuntu 20.04 or higher
### Running with python
- Python 3.6 or higher
- see requirements.txt for specific packages

## Main Features

1. **Automated enrollment**: The script can enroll a Ziti edge router using a provided JWT or by connecting to the controller to create a new router.
2. **Configuration generation**: The script generates a configuration file using Jinja2 templates, with support for customizing various settings.
3. **DNS handling**: The script can configure the system's DNS settings based on the operating system, currently supporting Ubuntu.
4. **Re-Registering**: The script can be used on a system already registerd & will stop the services before proceeding with the re-registration process.

## Examples

`./ziti_router_auto_enroll --jwt enrollment.txt`

- "Private" - This is the default edge-router configuration with the interface is that used as the default GW. This will create a edge listner. This will & only accept ziti SDK connections on port 443 & healthchecks on port 8081.


`./ziti_router_auto_enroll --jwt enrollment.txt --assumePublic`

- "Public" - This will change the default edge listner by using whatever external IP is used outbound instead of the local interface IP/name.   This also add a link listner using the same external IP. This will & accept ziti SDK connections on port 443 & other router links on port 80 & healthchecks on port 8081.

`./ziti_router_auto_enroll --jwt enrollment.txt --autoTunnelListener`
- "Private with local Tunneler enabled" - This will change the default to add a local Tunnel listner using the the interface is that used as the default GW & will attempt to configure the local DNS so the local interface is the first resolver for the OS.


## Main Options

The script take one positional argument, a jwt string which is optional.

- `-j JWT`, `--jwt JWT`: Path to file-based JWT
- `-p`, `--printConfig`: Print the generated configuration and exit
- `-t`, `--printTemplate`: Print the Jinja template used to create the config and exit
- `-n`, `--noHostname`: Don't use hostnames, only IP addresses for auto-generated config
- `-f`, `--force`: Forcefully proceed with re-enrollment
- `-l {DEBUG,INFO,WARNING,ERROR,CRITICAL}`, `--logLevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}`: Set the logging level (Default: INFO)
- `-v`, `--version`: Show the program's version number and exit

## Install Options

- `--logFile LOGFILE`: Specify the log file (Default: `{cwd}/{program_name}.log`)
- `--parametersFile PARAMETERSFILE`: File containing all parameters (JSON or YAML)
- `--installDir INSTALLDIR`: Installation directory for Openziti (Default: `/opt/ziti`)
- `--installVersion INSTALLVERSION`: Install a specific version (Default is to match Controller)
- `--downloadUrl DOWNLOADURL`: Bundle download URL (Default: `https://github.com/openziti/ziti/releases/latest/`)

## Configuration Options
### Router Identity Paths

- `--identityCert`: Path to certificate (Default: `{installDir}/certs/cert.pem`)
- `--identityServerCert`: Path to server chain (Default: `{installDir}/certs/server_cert.pem`)
- `--identityKey`: Path to key file (Default: `{installDir}/certs/key.pem`)
- `--identityCa`: Path to CA chain (Default: `{installDir}/certs/ca.pem`)

### Controller options

- `--controller`: Hostname or IP of Openziti controller
- `--controllerMgmtPort`: Controller Edge Port
- `--controllerFabricPort`: Controller Fabric Port

### HealthCheck Options

- `--disableHealthChecks`: Disable HealthChecks portion of router config
- `--ctrlPingCheckInterval`: How often to ping the controller (Default: 30)
- `--ctrlPingCheckTimeout`: Timeout the ping (Default: 15)
- `--ctrlPingCheckInitialDelay`: How long to wait before pinging the controller (Default: 15)

### Metrics Options

- `--disableMetrics`: Disable Metrics portion of router config
- `--reportInterval`: Reporting Interval (Default: 15)
- `--messageQueueSize`: Message Queue Size (Default: 10)

### Edge Options
- `--disableEdge`: Disable the Edge portion of router config
- `--heartbeatIntervalSeconds`: Edge heartbeatInterval in Seconds (Default: 60)
- `--csrCountry`: Country in certificate (Default: US)
- `--csrProvince`: Province in certificate (Default: NC)
- `--csrLocality`: Locality in certificate (Default: Charlotte)
- `--csrOrganization`: Organization in certificate (Default: NetFoundry)
- `--csrOrganizationalUnit`: OrganizationalUnit in certificate (Default: Ziti)
- `--csrSansEmail`: SANS Email
- `--csrSansDns`: List of SANS DNS names
- `--csrSansIp`: List of SANS IP Addresses
- `--csrSansUri`: List of SANS URIs
- `--apiProxyListener`: The interface and port that the Edge API should be served on.
    - Format: 'Listner'
      - Example: '0.0.0.0:1080'
- `--apiProxyUpstream`: The hostname and port combination to the ziti-controller hosted Edge API
    - Format: 'Upstream'
      - Example: '0.0.0.0:1080'

### Link Options
- `--linkDialers`: Link Dialers (Default: 'transport')
    - Format: BINDING BIND
    - Binding: The binding type ('transport')
    - Bind: The network interface used to dial the controller and router links can be ip or interface name.
      - Example: 'transport' '0.0.0.0'

- `--linkListeners`: Link Listener (Default: None)
    - Format: 'BINDING' 'BIND' 'ADVERTISE' 'OUTQUESIZE'
    - Binding: The binding type ('transport')
    - Bind: A protocol:host:port string on which network interface to listen on. 0.0.0.0 will listen on all interfaces
    - Advertise: The protocol:host:port combination other router should use to connect.
    - OutQueSize: The queue size for #TODO
      - Example: 'transport' 'tls:0.0.0.0:80' 'tls:myhost:80' '16'

### Listeners Options
- `--disableListeners`: Disable Listeners portion of router config
- `--assumePublic`: Attempt to use external lookup to assign default edge listener instead of {default_gw_adapter}
- `--edgeListeners`: Edge Binding Listener (Default: 'edge' 'tls:0.0.0.0:443' '{default_gw_adapter}:443')
    - Format: 'ADDRESS' 'ADVERTISE' 'MAXQUEUEDCONNECTS' 'MAXOUTSTANDINGCONNECTS' 'CONNECTTIMEOUTMS' 'LOOKUPAPISESSIONTIMEOUT'
    - Address: A protocol:host:port string on which network interface to listen on. 0.0.0.0 will listen on all interfaces
    - Advertise: The public hostname and port combination that Ziti SDKs should connect on.
    - MaxQueuedConnects: Set the maximum number of connect requests that are buffered and waiting to be acknowledged (1 to 5000, default 1000)
    - MaxOutstandingConnects: The maximum number of connects that have  begun hello synchronization (1 to 1000, default 16)
    - ConnectionTimeoutMS: The number of milliseconds to wait before a hello synchronization fails and closes the connection (30ms to 60000ms, default: 1000ms)
    - LookupApiSessionTimeout: How long to wait before timing out when looking up api-sessions after client connect. Default 5 seconds.
      - Example: 'tls:0.0.0.0:443' 'myhost:443' '1000' '16' '1000' '5'

- `--proxyListeners`: Proxy Binding Listener (Default: None)
    - Format: 'ADDRESS' 'SERVICE'
    - Address: A protocol:host:port string on which network interface to listen on. 0.0.0.0 will listen on all interfaces
    - Service: The name of the ziti service to connect.
      - Example: 'tcp:0.0.0.0:123' 'my_ntp_service'
      
- `--tunnelListener`: Tunnel Binding Listener (Default: None)
    - Format: 'MODE' 'RESOLVER' 'LANIF'
    - Mode: Tunnel mode ('tproxy', 'host', 'proxy')
    - Resolver: A protocol:host:port string on which network interface to listen on.
    - LanIf: The lan interface to create to create tproxy rules.
      - Example: 'tproxy' 'udp://127.0.0.1:53' 'eth0'
- `--autoTunnelListener`: Automatically add a local tproxy tunneler with the {default_gw_adapter} as the local resolver and LANIf

### Web Options
- `--webs`: Web Options (Default: 'health-check' '0.0.0.0:8081' '0.0.0.0:8081' 'health-checks')
    - Format: 'NAME' 'INTERFACE' 'ADDRESS' 'BINDING'
    - Name: Provides a name for this listener, used for logging output. Not required to be unique, but is highly suggested.
    - Interface: A host:port string on which network interface to listen on. 0.0.0.0 will listen on all interfaces
    - Address: The public address that external incoming requests will be able to resolve.
    - Binding: Specifies an API to bind to this webListener. Built-in APIs are
      - Example: 'health-check' '0.0.0.0:8081' '0.0.0.0:8081' 'health-checks'

## Router Creation Options

Create a new router on the controller before enrollment:

- `--adminUser`: Openziti Admin username
- `--adminPassword`: Openziti Admin password
- `--routerName`: Router name created in controller