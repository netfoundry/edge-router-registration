[![Pylint](https://github.com/netfoundry/edge-router-registration/actions/workflows/pylint.yml/badge.svg)](https://github.com/netfoundry/edge-router-registration/actions/workflows/pylint.yml)

# edge-router-registration

NetFoundry registration script.

This script is made up of two parts.  

1. A bootstrap script
1. The main registration script

## Bootstrap

The job of the bootstrap script is the download the latest version of the main script at run time, if the main doesn't exist or is older than 24hrs.


## Registration

The job of the registration script is to provide an easy way for a end user to register the NetFoundry Edge Router using a OTP(one time password).

The registration script is made of several parts.

* OS configuration
* NetFoundry configuration
* OpenZiti registration


### OS configuration

In order to run the edge-route in tunneler enabled modes, the OS needs to be configured to have the OpenZiti resolver as the first resolver.  This action requires a configuration be created for systemd-resolved. This configuration is depended on how the OS is configured, specifically what IP address is assigned & what interfaces exist.

### NetFoundry configuration

The NetFoundry console allows you to select if the ER is going to have "Link Listener".  Enabling this setting make the script attempt to lookup the external IP address & use it to advertise itself for other ER in the fabric mesh to connect to it.  This implies the ER should be publicaly accessible with inbound FW rules open for the fabric(80/tcp) & edge(443/tcp). The **default setting is disabled** which implies the ER is **NOT** going to advertise itself for inbound fabric connections & not publicaly accessible.  In this setting, the edge(443/tcp) is still allowed inbound, but only from the local subnet.

### OpenZiti registration

  The script accepts a JWT from NetFoundry & uses it to peform the OpenZiti *enrollment* process for the ER.