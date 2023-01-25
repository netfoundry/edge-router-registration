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