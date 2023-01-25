#!/usr/bin/env python
"""
NetFoundry Edge Router registration bootstrap script
"""
import os
import sys
import time
import subprocess
import tarfile
from tqdm import tqdm
import requests

def cleanup_file(file_name):
    """
    Cleanup a file
    """
    try:
        if os.path.exists(file_name):
            os.remove(file_name)
    except OSError:
        print("ERROR: Unable to remove file ", file_name)

def compare_dates(file_name):
    """
    Compare current date to file creation time, return True if it's older an 24hrs
    """
    current_time_in_seconds = time.time()
    if os.stat(file_name).st_mtime < current_time_in_seconds - 86400:
        return True
    return False

def download_file(source_url):
    """
    Download file & extract
    """
    try:
        file_name="router_registration.tar.gz"
        response = requests.get(source_url, stream=True, timeout=120)

        total_size = int(response.headers.get("content-length", 0))
        block_size = 1024  # 1 Kibibyte
        status_bar = tqdm(total=total_size, unit="iB", unit_scale=True, desc="Downloading")

        with open(file_name, "wb") as open_file:
            for data in response.iter_content(block_size):
                status_bar.update(len(data))
                open_file.write(data)
        status_bar.close()
        with tarfile.open(file_name) as downloaded_file:
            for member in downloaded_file.getmembers():
                downloaded_file.extract(member, "/opt/netfoundry/")
                os.remove(file_name)
    except OSError:
        print("Error: Unable to download binaries: ")
        sys.exit(1)

def root_check():
    """
    Check to see if this is running as root
    """
    if os.geteuid() >= 1:
        print("ERROR: This script must be run with root privileges, please use sudo or run as root")
        sys.exit(1)

def main():
    """
    Main logic
    """
    __version__ = '1.0.0'
    # change log
    # 1.0.0 - initial release

    # define static variables
    registration_script = "/opt/netfoundry/.router_reg"
    artifactory_url = "https://github.com/netfoundry/edge-router-registration/releases/latest/download/router_registration.tar.gz"

    # run root check
    root_check()

    # only compare if file exists
    do_update = False
    if os.path.exists(registration_script):
        # only update if it's older than 24hrs
        file_comparison = compare_dates(registration_script)
        if file_comparison:
            do_update = True
    else:
        do_update = True

    # only download if update is needed
    if do_update:
        cleanup_file(registration_script)
        download_file(artifactory_url)

    # run script
    sub_command = [registration_script] + sys.argv[1:]
    subprocess.run(sub_command)

# main
if __name__ == '__main__':
    main()
