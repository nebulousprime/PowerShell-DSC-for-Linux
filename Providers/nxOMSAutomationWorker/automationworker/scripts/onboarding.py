#!/usr/bin/env python2
#
# Copyright (C) Microsoft Corporation, All rights reserved.

import ConfigParser
import base64
import datetime
import os
import re
import shutil
import socket
import subprocess
import sys
from optparse import OptionParser

# append worker binary source path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from worker import configuration
from worker import httpclientfactory
from worker import linuxutil
from worker import serializerfactory
from worker import util

json = serializerfactory.get_serializer(sys.version_info)
configuration.clear_config()
configuration.set_config({configuration.PROXY_CONFIGURATION_PATH: "/etc/opt/microsoft/omsagent/proxy.conf",
                          configuration.WORKER_VERSION: "LinuxDIYRegister",
                          configuration.WORKING_DIRECTORY_PATH: "/tmp"})


def get_ip_address():
    try:
        return socket.gethostbyname(socket.gethostname())
    except:
        return "127.0.0.1"


def set_permission_recursive(permission, path):
    """Sets the permission for a specific path and it's child items recursively.

    Args:
        permission  : string, linux permission (i.e 770).
        path        : string, the target path.
    """
    cmd = ["chmod", "-R", permission, path]
    process, output, error = linuxutil.popen_communicate(cmd)
    if process.returncode != 0:
        raise Exception(
            "Unable to change permission of " + str(path) + " to " + str(permission) + ". Error : " + str(error))
    print "Permission changed to " + str(permission) + " for " + str(path)


def set_user_and_group_recursive(owning_username, owning_group_name, path):
    """Sets the owner for a specific path and it's child items recursively.

    Args:
        owning_username     : string, the owning user
        owning_group_name   : string, the owning group
        path                : string, the target path.
    """
    owners = owning_username + ":" + owning_group_name
    cmd = ["chown", "-R", owners, path]
    process, output, error = linuxutil.popen_communicate(cmd)
    if process.returncode != 0:
        raise Exception("Unable to change owner of " + str(path) + " to " + str(owners) + ". Error : " + str(error))
    print "Owner changed to " + str(owners) + " for " + str(path)


def generate_self_signed_certificate(certificate_path, key_path):
    """Creates a self-signed x509 certificate and key pair in the spcified path.

    Args:
        certificate_path    : string, the output path of the certificate
        key_path            : string, the output path of the key
    """
    cmd = ["openssl", "req", "-subj",
           "/C=US/ST=Washington/L=Redmond/O=Microsoft Corporation/OU=Azure Automation/CN=Hybrid Runbook Worker",
           "-new", "-newkey", "rsa:2048", "-days", "365", "-nodes", "-x509", "-keyout", key_path, "-out",
           certificate_path]
    process, certificate_creation_output, error = linuxutil.popen_communicate(cmd)
    if process.returncode != 0:
        raise Exception("Unable to create certificate/key. " + str(error))
    print "Certificate/Key created."


def sha256_digest(payload):
    """Sha256 digest of the specified payload.

    Args:
        payload : string, the payload to digest

    Returns:
        payload_hash : string, the sha256 hash of the payload
    """
    cmd = ['echo -n "' + str(json.dumps(json.dumps(payload))) + '" | openssl dgst -sha256 -binary']
    process, payload_hash, error = linuxutil.popen_communicate(cmd, shell=True)

    if process.returncode != 0:
        raise Exception("Unable to generate payload hash. " + str(error))

    return payload_hash


def generate_hmac(str_to_sign, secret):
    """Signs the specified string using the specified secret.

    Args:
        str_to_sign : string, the string to sign
        secret      : string, the secret used to sign

    Returns:
        signed_message : string, the signed str_to_sign
    """
    message = str_to_sign.encode('utf-8')
    secret = secret.encode('utf-8')
    cmd = ['echo -n "' + str(message) + '" | openssl dgst -sha256 -binary -hmac "' + str(secret) + '"']
    process, signed_message, error = linuxutil.popen_communicate(cmd, shell=True)

    if process.returncode != 0:
        raise Exception("Unable to generate signature. " + str(error))

    return signed_message


def create_worker_configuration_file(jrds_uri, automation_account_id, worker_group_name, machine_id,
                                     working_directory_path, state_directory_path, cert_path, key_path,
                                     registration_endpoint, workspace_id, thumbprint, vm_id, is_azure_vm, test_mode):
    """Creates the automation hybrid worker configuration file.

    Args:
        jrds_uri                : string, the jrds endpoint
        automation_account_id   : string, the automation account id
        worker_group_name       : string, the hybrid worker group name
        machine_id              : string, the machine id
        working_directory_path  : string, the hybrid worker working directory path
        state_directory_path    : string, the state directory path
        cert_path               : string, the the certificate path
        key_path                : string, the key path
        registration_endpoint   : string, the registration endpoint
        workspace_id            : string, the workspace id
        thumbprint              : string, the certificate thumbprint
        test_mode               : bool  , test mode

    Note:
        The generated file has to match the latest worker.conf template.
    """
    worker_conf_path = os.path.join(state_directory_path, "worker.conf")

    config = ConfigParser.ConfigParser()
    if os.path.isfile(worker_conf_path):
        config.read(worker_conf_path)
    conf_file = open(worker_conf_path, 'wb')

    worker_required_section = configuration.WORKER_REQUIRED_CONFIG_SECTION
    if not config.has_section(worker_required_section):
        config.add_section(worker_required_section)
    config.set(worker_required_section, configuration.CERT_PATH, cert_path)
    config.set(worker_required_section, configuration.KEY_PATH, key_path)
    config.set(worker_required_section, configuration.BASE_URI, jrds_uri)
    config.set(worker_required_section, configuration.ACCOUNT_ID, automation_account_id)
    config.set(worker_required_section, configuration.MACHINE_ID, machine_id)
    config.set(worker_required_section, configuration.HYBRID_WORKER_GROUP_NAME, worker_group_name)
    config.set(worker_required_section, configuration.WORKING_DIRECTORY_PATH, working_directory_path)

    worker_optional_section = configuration.WORKER_OPTIONAL_CONFIG_SECTION
    if not config.has_section(worker_optional_section):
        config.add_section(worker_optional_section)
    config.set(worker_optional_section, configuration.PROXY_CONFIGURATION_PATH,
               "/etc/opt/microsoft/omsagent/proxy.conf")
    config.set(worker_optional_section, configuration.STATE_DIRECTORY_PATH, state_directory_path)
    config.set(worker_optional_section, configuration.WORKER_TYPE, "diy")
    if test_mode is True:
        config.set(worker_optional_section, configuration.BYPASS_CERTIFICATE_VERIFICATION, True)
        config.set(worker_optional_section, configuration.DEBUG_TRACES, True)

    registration_metadata_section = "registration-metadata"
    if not config.has_section(registration_metadata_section):
        config.add_section(registration_metadata_section)
    config.set(registration_metadata_section, configuration.REGISTRATION_ENDPOINT, registration_endpoint)
    config.set(registration_metadata_section, configuration.WORKSPACE_ID, workspace_id)
    config.set(registration_metadata_section, configuration.CERTIFICATE_THUMBPRINT, thumbprint)
    config.set(registration_metadata_section, configuration.IS_AZURE_VM, str(is_azure_vm))
    config.set(registration_metadata_section, configuration.VM_ID, vm_id)

    config.write(conf_file)
    conf_file.close()


def get_autoregistered_worker_account_id():
    autoregistered_worker_conf_path = "/var/opt/microsoft/omsagent/state/automationworker/worker.conf"
    config = ConfigParser.ConfigParser()
    if os.path.isfile(autoregistered_worker_conf_path) is False:
        print "No diy worker found. Account validation skipped."
        return None

    config.read(autoregistered_worker_conf_path)
    account_id = config.get("worker-required", "account_id")
    print "Found existing worker for account id : " + str(account_id)
    return account_id


def extract_account_id_from_registration_endpoint(registration_endpoint):
    account_id = re.findall("[a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12}",
                            registration_endpoint.lower())
    if len(account_id) != 1:
        raise Exception("Invalid registration endpoint format.")
    return account_id[0]


def invoke_dmidecode():
    """Gets the dmidecode output from the host."""
    proc = subprocess.Popen(["su", "-", "root", "-c", "dmidecode"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    dmidecode, error = proc.communicate()
    if proc.poll() != 0:
        raise Exception("Unable to get dmidecode output : " + str(error))
    return dmidecode


def register(options):
    """Registers the machine against the automation agent service.

    Args:
        options : dict, the options dictionary
    """
    registration_endpoint = options.registration_endpoint
    automation_account_key = options.automation_account_key
    hybrid_worker_group_name = options.hybrid_worker_group_name
    workspace_id = options.workspace_id

    # assert workspace exists on the box
    state_base_path = "/var/opt/microsoft/omsagent/" + workspace_id + "/state/"
    working_directory_base_path = "/var/opt/microsoft/omsagent/" + workspace_id + "/run/"
    if os.path.exists(state_base_path) is False or os.path.exists(working_directory_base_path) is False:
        raise Exception("Invalid workspace id. Is the specified workspace id registered as the OMSAgent "
                        "primary worksapce?")

    diy_account_id = extract_account_id_from_registration_endpoint(registration_endpoint)
    if get_autoregistered_worker_account_id() != diy_account_id:
        raise Exception("Cannot register, conflicting worker already registered.")

    diy_state_base_path = os.path.join(state_base_path, os.path.join("automationworker", "diy"))
    diy_working_directory_base_path = os.path.join(working_directory_base_path, os.path.join("automationworker", "diy"))
    worker_conf_path = os.path.join(diy_state_base_path, "worker.conf")

    if os.path.isfile(worker_conf_path) is True:
        raise Exception("Unable to register, an existing worker was found. Please deregister any exiting worker and "
                        "try again.")

    certificate_path = os.path.join(diy_state_base_path, "worker_diy.crt")
    key_path = os.path.join(diy_state_base_path, "worker_diy.key")
    machine_id = util.generate_uuid()

    # generate state path (certs/conf will be dropped in this path)
    if os.path.isdir(diy_state_base_path) is False:
        os.makedirs(diy_state_base_path)
    generate_self_signed_certificate(certificate_path=certificate_path, key_path=key_path)
    issuer, subject, thumbprint = linuxutil.get_cert_info(certificate_path)

    # try to extract optional metadata
    unknown = "Unknown"
    asset_tag = unknown
    vm_id = unknown
    is_azure_vm = unknown
    try:
        dmidecode = invoke_dmidecode()
        is_azure_vm = linuxutil.is_azure_vm(dmidecode)
        if is_azure_vm:
            asset_tag = linuxutil.get_azure_vm_asset_tag()
        else:
            asset_tag = False
        vm_id = linuxutil.get_vm_unique_id_from_dmidecode(sys.byteorder, dmidecode)
    except Exception, e:
        print str(e)
        pass

    # generate payload for registration request
    date = datetime.datetime.utcnow().isoformat() + "0-00:00"
    payload = {'RunbookWorkerGroup': hybrid_worker_group_name,
               "MachineName": socket.gethostname(),
               "IpAddress": get_ip_address(),
               "Thumbprint": thumbprint,
               "Issuer": issuer,
               "OperatingSystem": 2,
               "SMBIOSAssetTag": asset_tag,
               "VirtualMachineId": vm_id,
               "Subject": subject}

    # the signature generation is based on agent service contract
    payload_hash = sha256_digest(payload)
    b64encoded_payload_hash = base64.b64encode(payload_hash)
    signature = generate_hmac(b64encoded_payload_hash + "\n" + date, automation_account_key)
    b64encoded_signature = base64.b64encode(signature)

    headers = {'Authorization': 'Shared ' + b64encoded_signature,
               'ProtocolVersion': "2.0",
               'x-ms-date': date,
               "Content-Type": "application/json"}

    # agent service registration request
    http_client_factory = httpclientfactory.HttpClientFactory(certificate_path, key_path, options.test)
    http_client = http_client_factory.create_http_client(sys.version_info)
    url = registration_endpoint + "/HybridV2(MachineId='" + machine_id + "')"
    response = http_client.put(url, headers=headers, data=payload)

    if response.status_code != 200:
        raise Exception("Failed to register worker. [response_status=" + str(response.status_code) + "]")

    registration_response = json.loads(response.raw_data)
    account_id = registration_response["AccountId"]
    create_worker_configuration_file(registration_response["jobRuntimeDataServiceUri"], account_id,
                                     hybrid_worker_group_name, machine_id, diy_working_directory_base_path,
                                     diy_state_base_path, certificate_path, key_path, registration_endpoint,
                                     workspace_id, thumbprint, vm_id, is_azure_vm, options.test)

    # generate working directory path
    if os.path.isdir(diy_working_directory_base_path) is False:
        os.makedirs(diy_working_directory_base_path)

    # set appropriate permission to the created directory
    set_user_and_group_recursive(owning_username="omsagent", owning_group_name="omiusers", path=diy_state_base_path)
    set_permission_recursive(permission="770", path=diy_state_base_path)

    set_user_and_group_recursive(owning_username="nxautomation", owning_group_name="omiusers",
                                 path=diy_working_directory_base_path)
    set_permission_recursive(permission="770", path=diy_working_directory_base_path)

    print "Registration successful!"


def deregister(options):
    registration_endpoint = options.registration_endpoint
    automation_account_key = options.automation_account_key
    workspace_id = options.workspace_id

    # assert workspace exists on the box
    state_base_path = "/var/opt/microsoft/omsagent/" + workspace_id + "/state/"
    working_directory_base_path = "/var/opt/microsoft/omsagent/" + workspace_id + "/run/"
    if os.path.exists(state_base_path) is False or os.path.exists(working_directory_base_path) is False:
        raise Exception("Invalid workspace id. Is the specified workspace id registered as the OMSAgent "
                        "primary worksapce?")

    diy_state_base_path = os.path.join(state_base_path, os.path.join("automationworker", "diy"))
    diy_working_directory_base_path = os.path.join(working_directory_base_path, os.path.join("automationworker", "diy"))
    worker_conf_path = os.path.join(diy_state_base_path, "worker.conf")
    certificate_path = os.path.join(diy_state_base_path, "worker_diy.crt")
    key_path = os.path.join(diy_state_base_path, "worker_diy.key")

    if os.path.exists(worker_conf_path) is False:
        raise Exception("Unable to deregister, no worker configuration found on disk.")

    if os.path.exists(certificate_path) is False or os.path.exists(key_path) is False:
        raise Exception("Unable to deregister, no worker certificate/key found on disk.")

    issuer, subject, thumbprint = linuxutil.get_cert_info(certificate_path)

    if os.path.exists(worker_conf_path) is False:
        raise Exception("Missing worker configuration.")

    if os.path.exists(certificate_path) is False:
        raise Exception("Missing worker certificate.")

    if os.path.exists(key_path) is False:
        raise Exception("Missing worker key.")

    config = ConfigParser.ConfigParser()
    config.read(worker_conf_path)
    machine_id = config.get("worker-required", "machine_id")

    # generate payload for registration request
    date = datetime.datetime.utcnow().isoformat() + "0-00:00"
    payload = {"Thumbprint": thumbprint,
               "Issuer": issuer,
               "Subject": subject}

    # the signature generation is based on agent service contract
    payload_hash = sha256_digest(payload)
    b64encoded_payload_hash = base64.b64encode(payload_hash)
    signature = generate_hmac(b64encoded_payload_hash + "\n" + date, automation_account_key)
    b64encoded_signature = base64.b64encode(signature)

    headers = {'Authorization': 'Shared ' + b64encoded_signature,
               'ProtocolVersion': "2.0",
               'x-ms-date': date,
               "Content-Type": "application/json"}

    # agent service registration request
    http_client_factory = httpclientfactory.HttpClientFactory(certificate_path, key_path, options.test)
    http_client = http_client_factory.create_http_client(sys.version_info)
    url = registration_endpoint + "/Hybrid(MachineId='" + machine_id + "')"
    response = http_client.delete(url, headers=headers, data=payload)

    if response.status_code != 200:
        raise Exception("Failed to deregister worker. [response_status=" + str(response.status_code) + "]")
    if response.status_code == 404:
        raise Exception("Unable to deregister. Worker not found.")
    print "Successfuly deregistered worker."

    print "Cleaning up left over directories."

    try:
        shutil.rmtree(diy_state_base_path)
        print "Removed state directory."
    except:
        raise Exception("Unable to remove state directory base path.")

    try:
        shutil.rmtree(diy_working_directory_base_path)
        print "Removed working directory."
    except:
        raise Exception("Unable to remove working directory base path.")


def environment_prerequisite_validation():
    """Validates that basic environment requirements are met for the onboarding operations."""

    # is running as root
    if os.getuid() != 0:
        raise Exception("You need to run this script as root to register a new automation worker.")

    nxautomation_username = "nxautomation"
    if linuxutil.is_existing_user(nxautomation_username) is False:
        raise Exception("Missing user : " + nxautomation_username + ". Are you running the lastest OMSAgent version?")

    omsagent_username = "omsagent"
    if linuxutil.is_existing_user(omsagent_username) is False:
        raise Exception("Missing user : " + omsagent_username + ".")

    omiusers_group_name = "omiusers"
    if linuxutil.is_existing_group(omiusers_group_name) is False:
        raise Exception("Missing group : " + omiusers_group_name + ".")

    nxautomation_group_name = "nxautomation"
    if linuxutil.is_existing_group(omiusers_group_name) is False:
        raise Exception("Missing group : " + nxautomation_group_name + ".")


def get_options_and_arguments():
    parser = OptionParser(usage="usage: %prog -e endpoint -k key -g groupname",
                          version="%prog " + str(configuration.get_worker_version()))
    parser.add_option("-e", "--endpoint", dest="registration_endpoint", help="Agent service registration endpoint.")
    parser.add_option("-k", "--key", dest="automation_account_key", help="Automation account primary/secondary key.")
    parser.add_option("-g", "--groupname", dest="hybrid_worker_group_name", help="Hybrid worker group name.")
    parser.add_option("-w", "--workspaceid", dest="workspace_id", help="Workspace id.")
    parser.add_option("-r", "--register", action="store_true", dest="register", default=False)
    parser.add_option("-d", "--deregister", action="store_true", dest="deregister", default=False)
    parser.add_option("-t", "--test", action="store_true", dest="test", default=False)
    (options, args) = parser.parse_args()

    if options.register is False and options.deregister is False:
        raise Exception("Please specify the onboarding action to perform (--register | --deregister).")

    # --register requirements
    if options.register is True and (options.registration_endpoint is not None
                                     and options.automation_account_key is not None
                                     and options.hybrid_worker_group_name is not None
                                     and options.workspace_id is not None) is False:
        parser.print_help()
        sys.exit(-1)

    # --deregister requirements
    if options.deregister is True and (options.registration_endpoint is not None
                                       and options.automation_account_key is not None
                                       and options.hybrid_worker_group_name is not None
                                       and options.workspace_id is not None) is False:
        parser.print_help()
        sys.exit(-1)
    return options, args


def main():
    options, args = get_options_and_arguments()
    environment_prerequisite_validation()

    if options.register is True:
        register(options)
    elif options.deregister is True:
        deregister(options)


if __name__ == "__main__":
    main()
