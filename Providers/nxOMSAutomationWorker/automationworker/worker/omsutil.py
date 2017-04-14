#!/usr/bin/env python2
#
# Copyright (C) Microsoft Corporation, All rights reserved.

from optparse import OptionParser
import sys
import os
import pwd
import grp

# append worker binary source path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from worker import configuration
from worker import serializerfactory
from worker import linuxutil

json = serializerfactory.get_serializer(sys.version_info)
configuration.clear_config()
configuration.set_config({configuration.PROXY_CONFIGURATION_PATH: "/etc/opt/microsoft/omsagent/proxy.conf",
                          configuration.WORKER_VERSION: "OMSUtil",
                          configuration.WORKING_DIRECTORY_PATH: "/tmp"})

USERNAME_NXAUTOMATION = "nxautomation"
GROUPNAME_NXAUTOMATION = "nxautomation"
GROUPNAME_OMSAGENT = "omsagent"


def initialize():
    """Initializes the OMS environment. Meant to be executed everytime the resource's set method is invoked.
    Steps:
        - Sets omsagent group to nxautomation user (if needed).
        - Sets group read permission to MSFT keyring.gpg
        - Sets group read and execute to the OMS certificate folder.

    Args:
        None
    """
    # add nxautomation to omsagent group
    nxautomation_uid = int(pwd.getpwnam(USERNAME_NXAUTOMATION).pw_uid)
    if os.getuid() == nxautomation_uid:
        omsagent_group = grp.getgrnam(GROUPNAME_OMSAGENT)
        if USERNAME_NXAUTOMATION not in omsagent_group.gr_mem:
            process, output, error = linuxutil.popen_communicate(["sudo", "/usr/sbin/usermod", "-g", "nxautomation",
                                                                  "-a", "-G", "omsagent,omiusers", "nxautomation"])
            if process.returncode != 0:
                raise Exception("Unable to add nxautomation to omsagent group. Error: " + str(error))
            else:
                print "Successfully added omsagent secondary group to nxautomation user."

    # change permissions for the keyring.gpg
    process, output, error = linuxutil.popen_communicate(["sudo", "chmod", "g+r",
                                                          "/etc/opt/omi/conf/omsconfig/keyring.gpg"])
    if process.returncode != 0:
        raise Exception("Unable set group permission to keyring. Error: " + str(error))
    else:
        print "Successfully set group permissions to keyring.gpg."

    # change permission for the certificate folder, oms.crt and oms.key
    process, output, error = linuxutil.popen_communicate(["sudo", "chmod", "g+rx", "-R",
                                                          "/etc/opt/microsoft/omsagent/certs"])
    if process.returncode != 0:
        raise Exception("Unable set group permissions to certificate folder. Error: " + str(error))
    else:
        print "Successfully set group permissions to certificate folder."

    # change owner for the worker working directory
    process, output, error = linuxutil.popen_communicate(["sudo", "chown", "nxautomation:omiusers", "-R",
                                                          "/var/opt/microsoft/omsagent/run/automationworker"])
    if process.returncode != 0:
        raise Exception("Unable set group owner to certificate folder. Error: " + str(error))
    else:
        print "Successfully set group permissions to certificate folder."

    process, output, error = linuxutil.popen_communicate(["sudo", "chmod", "g+rx", "-R",
                                                          "/var/opt/microsoft/omsagent/run/automationworker"])
    if process.returncode != 0:
        raise Exception("Unable set owners of certificate folder. Error: " + str(error))
    else:
        print "Successfully set owners of certificate folder."


def dmidecode():
    """Returns the content of dmidecode."""
    print linuxutil.invoke_dmidecode()


def main():
    parser = OptionParser(usage="usage: %prog [--initialize, --dmidecode]",
                          version="%prog " + str(configuration.get_worker_version()))
    parser.add_option("--initialize", action="store_true", dest="initialize", default=False)
    parser.add_option("--dmidecode", action="store_true", dest="dmidecode", default=False)
    (options, args) = parser.parse_args()

    nxautomation_uid = int(pwd.getpwnam("nxautomation").pw_uid)
    if os.getuid() != nxautomation_uid:
        raise Exception("OMSUtil can only be ran as nxautomation user.")

    if options.initialize is True:
        initialize()
    elif options.dmidecode is True:
        dmidecode()
    else:
        raise Exception("No option specified.")


if __name__ == "__main__":
    main()
