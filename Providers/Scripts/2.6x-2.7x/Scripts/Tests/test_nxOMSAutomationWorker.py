#!/usr/bin/env python
#============================================================================
# Copyright (c) Microsoft Corporation. All rights reserved. See license.txt for license information.
#============================================================================


# How to run this test file
# cd to PowerShell-DSC-for-Linux/Providers/Scripts/<Python version>/Scripts/Tests
# invoke this file with the proprer python version as super user
import os
import sys
import grp
import imp
import subprocess
import pwd
import shutil
import ConfigParser

try:
    import unittest2
except:
    os.system('tar -zxvf ./unittest2-0.5.1.tar.gz')
    sys.path.append(os.path.realpath('./unittest2-0.5.1'))
    import unittest2

sys.path.append('.')
sys.path.append(os.path.realpath('./Scripts'))
os.chdir('../..')
nxOMSAutomationWorker=imp.load_source('nxOMSAutomationWorker', './Scripts/nxOMSAutomationWorker.py')

class nxOMSAutomationWorkerTestCases(unittest2.TestCase):
    """
    Test Case for nxOMSAutomationWorker.py
    """
    workspace_id = 'cfd4ef08-4011-428a-8947-0c2f4605980f'
    agent_id = 'cfd4ef08-4011-428a-8947-0c2f4605980g'
    AzureDnsAgentSvcZone = 'agentsvc.azure-automation.net'
    temp_run_dir = os.path.join(os.getcwd(), 'Scripts/Tests/temp')
    dummyFileLocation = os.path.join(os.getcwd(), 'Scripts/Tests/dummy_nxOMSAutomationWorker_files')

    nxOMSAutomationWorker.WORKER_CONF_DIR = temp_run_dir
    nxOMSAutomationWorker.OMS_CONF_FILE_PATH = os.path.join(temp_run_dir, "oms.conf")
    nxOMSAutomationWorker.AUTO_REGISTERED_WORKER_CONF_PATH = os.path.join(temp_run_dir, "worker.conf")
    nxOMSAutomationWorker.WORKER_MANAGER_START_PATH = os.path.join(dummyFileLocation, 'main.py')
    nxOMSAutomationWorker.DSC_RESOURCE_VERSION_FILE = os.path.join(dummyFileLocation, 'VERSION')
    nxOMSAutomationWorker.LOCAL_LOG_LOCATION = os.path.join(temp_run_dir, 'nxOMSAutomationWorker.log')
    nxOMSAutomationWorker.LOG_LOCALLY = True
    nxOMSAutomationWorker.OMS_ADMIN_CONFIG_FILE = os.path.join(dummyFileLocation, 'omsadmin.conf')
    nxOMSAutomationWorker.DIY_WORKER_CONF_PATH = nxOMSAutomationWorker.AUTO_REGISTERED_WORKER_CONF_PATH

    automation_user = "nxautomation"

    def create_nxautomation_user_and_group(self):
        try:
            grp.getgrnam(self.automation_user)
        except KeyError:
            # group nxautomation not found, create one
            subprocess.call(["groupadd", "-r", self.automation_user])
        try:
            pwd.getpwnam(self.automation_user)
        except KeyError:
            # user nxautomation does not exist, create one
            if subprocess.call(
                    ["useradd", "-r", "-c", "nxOMSAutomation", "-d", "/var/opt/microsoft/omsagent/run", "-g",
                     self.automation_user, "-s", "/bin/bash", self.automation_user]) != 0:
                raise OSError("could not create %s user" % self.automation_user)
            if subprocess.call(
                    ["/usr/sbin/usermod", "-g", self.automation_user, "-a", "-G", "omsagent", "-G", "omiusers",
                     self.automation_user]) != 0:
                raise OSError("could not add %s to groups omsaget and omiusers", self.automation_user)
            if subprocess.call(["chmod", "-R", "0777", self.dummyFileLocation]) != 0:
                raise OSError("could not change permissions for dummy file")

    def remove_nxautomation_user_and_group(self):
        subprocess.call(["userdel", self.automation_user])

    def config_files_are_equivalent(self, config_orig_file, config_other_file):

        conf_orig = ConfigParser.ConfigParser()
        conf_orig.read(config_orig_file)
        conf_other = ConfigParser.ConfigParser()
        conf_other.read(config_other_file)
        #compare sections
        orig_sections = set(conf_orig.sections())
        other_sections = set(conf_other.sections())
        if orig_sections != other_sections:
            return False

        for section in orig_sections:
            orig_options = set (conf_orig.options(section))
            other_options = set (conf_other.options(section))
            if orig_options != other_options:
                return False
            for option in orig_options:
                orig_option = conf_orig.get(section, option)
                other_option = conf_orig.get(section, option)
                if orig_option != other_option:
                    return False
        return True


    def setUp(self):
        """
        Setup Test resources
        """
        if not os.path.isdir(self.temp_run_dir):
            os.mkdir(self.temp_run_dir, 0777)
        # create nxautomation user on the machine
        self.create_nxautomation_user_and_group()
        subprocess.call(["sudo", "pkill", "-u", self.automation_user])
        shutil.copyfile(os.path.join(self.dummyFileLocation, "worker.conf"),
                        nxOMSAutomationWorker.AUTO_REGISTERED_WORKER_CONF_PATH)

    def tearDown(self):
        """
        Remove test resoruces
        """
        subprocess.call(["sudo", "pkill", "-u", self.automation_user])
        shutil.rmtree(self.temp_run_dir, ignore_errors=True)
        self.remove_nxautomation_user_and_group()

    def test_can_start_verify_kill_worker_manager(self):
        shutil.copyfile(os.path.join(self.dummyFileLocation, "oms_conf_auto_manual.conf"),
                        nxOMSAutomationWorker.OMS_CONF_FILE_PATH)
        nxOMSAutomationWorker.start_worker_manager_process(self.workspace_id)
        pid, version = nxOMSAutomationWorker.get_worker_manager_pid_and_version(self.workspace_id)
        self.assertTrue(nxOMSAutomationWorker.is_worker_manager_running_latest_version(self.workspace_id))
        self.assertTrue(pid > 0)
        self.assertTrue(version == "1.4")

        nxOMSAutomationWorker.kill_worker_manager(self.workspace_id)
        self.assertFalse(nxOMSAutomationWorker.is_worker_manager_running_latest_version(self.workspace_id))
        pid, version = nxOMSAutomationWorker.get_worker_manager_pid_and_version(self.workspace_id)
        self.assertTrue(pid == -1)
        os.remove(nxOMSAutomationWorker.OMS_CONF_FILE_PATH)

    def test_parsing_parameters_and_creation_of_omsconf(self):
        auto_enabled_manual_enabled = "[{\"WorkspaceId\":\"%s\",\"AzureDnsAgentSvcZone\":\"df-agentsvc.azure-automation.net\",\"Solutions\":{\"Updates\":{\"Enabled\":true},\"AzureAutomation\":{\"Enabled\":true,\"Parameter1\":\"PARAM_11\",\"Parameter2\":\"PARAM_12\"}}}]" % self.workspace_id
        auto_disabled_manual_enabled = "[{\"WorkspaceId\":\"%s\",\"AzureDnsAgentSvcZone\":\"df-agentsvc.azure-automation.net\",\"Solutions\":{\"Updates\":{\"Enabled\":false},\"AzureAutomation\":{\"Enabled\":true,\"Parameter1\":\"PARAM_11\",\"Parameter2\":\"PARAM_12\"}}}]" % self.workspace_id
        auto_enabled_manual_disabled = "[{\"WorkspaceId\":\"%s\",\"AzureDnsAgentSvcZone\":\"df-agentsvc.azure-automation.net\",\"Solutions\":{\"Updates\":{\"Enabled\":true},\"AzureAutomation\":{\"Enabled\":false,\"Parameter1\":\"PARAM_11\",\"Parameter2\":\"PARAM_12\"}}}]" % self.workspace_id
        auto_disabled_manual_disabled = "[{\"WorkspaceId\":\"%s\",\"AzureDnsAgentSvcZone\":\"df-agentsvc.azure-automation.net\",\"Solutions\":{\"Updates\":{\"Enabled\":false},\"AzureAutomation\":{\"Enabled\":false,\"Parameter1\":\"PARAM_11\",\"Parameter2\":\"PARAM_12\"}}}]" % self.workspace_id

        if os.path.isfile(nxOMSAutomationWorker.OMS_CONF_FILE_PATH):
            os.remove(nxOMSAutomationWorker.OMS_CONF_FILE_PATH)
        settings = nxOMSAutomationWorker.read_settings_from_mof_json(
            auto_enabled_manual_enabled)
        nxOMSAutomationWorker.write_omsconf_file(settings.workspace_id, settings.updates_enabled,
                                                 settings.diy_enabled)
        self.assertTrue(self.config_files_are_equivalent(os.path.join(self.dummyFileLocation, "oms_conf_auto_manual.conf"),
                                    nxOMSAutomationWorker.OMS_CONF_FILE_PATH))

        if os.path.isfile(nxOMSAutomationWorker.OMS_CONF_FILE_PATH):
            os.remove(nxOMSAutomationWorker.OMS_CONF_FILE_PATH)
        settings = nxOMSAutomationWorker.read_settings_from_mof_json(
            auto_disabled_manual_enabled)
        nxOMSAutomationWorker.write_omsconf_file(settings.workspace_id, settings.updates_enabled,
                                                 settings.diy_enabled)
        self.assertTrue(self.config_files_are_equivalent(os.path.join(self.dummyFileLocation, "oms_conf_manual.conf"),
                                    nxOMSAutomationWorker.OMS_CONF_FILE_PATH))

        if os.path.isfile(nxOMSAutomationWorker.OMS_CONF_FILE_PATH):
            os.remove(nxOMSAutomationWorker.OMS_CONF_FILE_PATH)
        settings = nxOMSAutomationWorker.read_settings_from_mof_json(
            auto_enabled_manual_disabled)
        nxOMSAutomationWorker.write_omsconf_file(settings.workspace_id, settings.updates_enabled,
                                                 settings.diy_enabled)
        self.assertTrue(self.config_files_are_equivalent(os.path.join(self.dummyFileLocation, "oms_conf_auto.conf"),
                                    nxOMSAutomationWorker.OMS_CONF_FILE_PATH))

        if os.path.isfile(nxOMSAutomationWorker.OMS_CONF_FILE_PATH):
            os.remove(nxOMSAutomationWorker.OMS_CONF_FILE_PATH)
        settings = nxOMSAutomationWorker.read_settings_from_mof_json(
            auto_disabled_manual_disabled)
        nxOMSAutomationWorker.write_omsconf_file(settings.workspace_id, settings.updates_enabled,
                                                 settings.diy_enabled)
        self.assertTrue(self.config_files_are_equivalent(os.path.join(self.dummyFileLocation, "oms_conf_none.conf"),
                                    nxOMSAutomationWorker.OMS_CONF_FILE_PATH))

    def test_is_oms_config_consistent_with_mof(self):
        dummy_oms_conf_filepaths = [os.path.join(self.dummyFileLocation, "oms_conf_auto_manual.conf"),
                                    os.path.join(self.dummyFileLocation, "oms_conf_manual.conf"),
                                    os.path.join(self.dummyFileLocation, "oms_conf_auto.conf"),
                                    os.path.join(self.dummyFileLocation, "oms_conf_none.conf")
                                    ]
        valid_results = {dummy_oms_conf_filepaths[0]: [True, True],
                         dummy_oms_conf_filepaths[1]: [False, True],
                         dummy_oms_conf_filepaths[2]: [True, False],
                         dummy_oms_conf_filepaths[3]: [False, False],
                         }
        for updates_enabled in [True, False]:
            for diy_enabled in [True, False]:
                for dummy_oms_conf_file_path in dummy_oms_conf_filepaths:
                    result = nxOMSAutomationWorker.is_oms_config_consistent_with_mof(updates_enabled,
                                                                                     diy_enabled,
                                                                                     dummy_oms_conf_file_path)
                    updates_expected_value, diy_expected_value = valid_results[dummy_oms_conf_file_path]
                    if updates_enabled == updates_expected_value and diy_enabled == diy_expected_value:
                        self.assertTrue(result)
                    else:
                        self.assertFalse(result)

    def test_get_diy_account_id(self):
        self.assertTrue(nxOMSAutomationWorker.get_diy_account_id() == "cfd4ef08-4011-428a-8947-0c2f4605980h")
        os.remove(nxOMSAutomationWorker.AUTO_REGISTERED_WORKER_CONF_PATH)
        self.assertFalse(nxOMSAutomationWorker.get_diy_account_id())

    def test_get_stray_worker_and_manager_pids(self):
        processes = [
            '1000 python /opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/hybridworker.py /var/opt/microsoft/omsagent/state/automationworker/worker.conf managed rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f rversion:1.4',
            '1001 python /opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/hybridworker.py /var/opt/microsoft/omsagent/state/automationworker/worker.conf managed rworkspace:dfd4ef08-4011-428a-8947-0c2f4605980f rversion:1.4',
            '1002 python /opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/main.py /var/opt/microsoft/omsagent/state/automationworker/oms.conf rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f 1.4',
            '1003 python /opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/main.py /var/opt/microsoft/omsagent/state/automationworker/oms.conf rworkspace:efd4ef08-4011-428a-8947-0c2f4605980f 1.4',
            '']
        stray_processes = nxOMSAutomationWorker.get_stray_worker_and_manager_wsids(processes, self.workspace_id)
        self.assertTrue(stray_processes == set(
            ['dfd4ef08-4011-428a-8947-0c2f4605980f', 'efd4ef08-4011-428a-8947-0c2f4605980f']))

        processes = [
            '1000 python /opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/hybridworker.py /var/opt/microsoft/omsagent/state/automationworker/worker.conf managed rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f rversion:1.4',
            '1001 python /opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/hybridworker.py /var/opt/microsoft/omsagent/state/automationworker/worker.conf managed rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f rversion:1.4',
            '1002 python /opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/main.py /var/opt/microsoft/omsagent/state/automationworker/oms.conf rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f 1.4',
            '1003 python /opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/main.py /var/opt/microsoft/omsagent/state/automationworker/oms.conf rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f 1.4',
            '']
        stray_processes = nxOMSAutomationWorker.get_stray_worker_and_manager_wsids(processes, self.workspace_id)
        self.assertFalse(stray_processes)

        processes = ['']
        stray_processes = nxOMSAutomationWorker.get_stray_worker_and_manager_wsids(processes, self.workspace_id)
        self.assertFalse(stray_processes)

    def test_is_any_1_4_process_running(self):
        processes = [
            '1002 python %s /var/opt/microsoft/omsagent/state/automationworker/oms.conf rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f 1.4' % nxOMSAutomationWorker.WORKER_MANAGER_START_PATH,
            '1003 python %s /var/opt/microsoft/omsagent/state/automationworker/oms.conf rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f 1.5.0.0' % nxOMSAutomationWorker.WORKER_MANAGER_START_PATH,
            '']
        self.assertTrue(nxOMSAutomationWorker.is_any_1_4_process_running(processes, self.workspace_id))

        processes = [
            '1000 python /opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/hybridworker.py /var/opt/microsoft/omsagent/state/automationworker/worker.conf managed rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f rversion:1.5.0.0',
            '1001 python /opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/hybridworker.py /var/opt/microsoft/omsagent/state/automationworker/worker.conf managed rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f rversion:1.5.0.0',
            '1002 python %s /var/opt/microsoft/omsagent/state/automationworker/oms.conf rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f 1.5.0.0' % nxOMSAutomationWorker.WORKER_MANAGER_START_PATH,
            '1003 python %s /var/opt/microsoft/omsagent/state/automationworker/oms.conf rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f 1.5.0.0' % nxOMSAutomationWorker.WORKER_MANAGER_START_PATH,
            '']
        self.assertFalse(nxOMSAutomationWorker.is_any_1_4_process_running(processes, self.workspace_id))

        processes = [
            '1000 python /opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/hybridworker.py /var/opt/microsoft/omsagent/state/automationworker/worker.conf managed rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f rversion:1.5.0.0',
            '1001 python /opt/microsoft/omsconfig/modules/nxOMSAutomationWorker/DSCResources/MSFT_nxOMSAutomationWorkerResource/automationworker/worker/hybridworker.py /var/opt/microsoft/omsagent/state/automationworker/worker.conf managed rworkspace:dfd4ef08-4011-428a-8947-0c2f4605980f rversion:1.4',
            '1002 python %s /var/opt/microsoft/omsagent/state/automationworker/oms.conf rworkspace:dfd4ef08-4011-428a-8947-0c2f4605980f 1.4' % nxOMSAutomationWorker.WORKER_MANAGER_START_PATH,
            '1003 python %s /var/opt/microsoft/omsagent/state/automationworker/oms.conf rworkspace:cfd4ef08-4011-428a-8947-0c2f4605980f 1.5.0.0' % nxOMSAutomationWorker.WORKER_MANAGER_START_PATH,
            '']
        self.assertFalse(nxOMSAutomationWorker.is_any_1_4_process_running(processes, self.workspace_id))


if __name__ == '__main__':
    s1 = unittest2.TestLoader().loadTestsFromTestCase(nxOMSAutomationWorkerTestCases)
    all_tests = unittest2.TestSuite([s1])
    unittest2.TextTestRunner(stream=sys.stdout, verbosity=3).run(all_tests)