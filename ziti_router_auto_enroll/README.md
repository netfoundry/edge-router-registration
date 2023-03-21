# Ziti Router Auto Enroll

This Python script automates the process of enrolling and configuring a Ziti edge router. The script takes care of generating the configuration file, handling the enrollment process, and setting up DNS settings.

## Requirements

- Python 3.6 or higher
- see requirements.txt for specific packages

## Main Features

1. **Automated enrollment**: The script can enroll a Ziti edge router using a provided JWT or by connecting to the controller to create a new router.
2. **Configuration generation**: The script generates a configuration file using Jinja2 templates, with support for customizing various settings.
3. **DNS handling**: The script can configure the system's DNS settings based on the operating system, currently supporting Ubuntu.
4. **Re-Registering**: The script can be used on a system already registerd & will stop the services before proceeding with the re-registration process.

## Limitations

- The script currently supports Ubuntu for DNS handling. Support for other operating systems might be added in the future.
