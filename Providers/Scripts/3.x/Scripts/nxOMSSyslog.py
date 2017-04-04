#!/usr/bin/env python
#============================================================================
# Copyright (C) Microsoft Corporation, All rights reserved.
#============================================================================

import os
import imp
import re
import codecs
from functools import reduce
protocol = imp.load_source('protocol', '../protocol.py')
nxDSCLog = imp.load_source('nxDSCLog', '../nxDSCLog.py')

LG = nxDSCLog.DSCLog

rsyslog_conf_path = '/etc/rsyslog.conf'
rsyslog_inc_conf_path = '/etc/rsyslog.d/95-omsagent.conf'
syslog_ng_conf_path = '/etc/syslog-ng/syslog-ng.conf'
sysklog_conf_path='/etc/syslog.conf'
oms_syslog_ng_conf_path = '/etc/opt/omi/conf/omsconfig/syslog-ng-oms.conf'
oms_rsyslog_conf_path = '/etc/opt/omi/conf/omsconfig/rsyslog-oms.conf'
conf_path = ''
multi_homed = None


def init_vars(SyslogSource, WorkspaceID):
    global conf_path
    global multi_homed

    for source in SyslogSource:
        if source['Severities'] is not None:
            if 'value' in dir(source['Severities']):
                source['Severities'] = source['Severities'].value
        if 'value' in dir(source['Facility']):
            source['Facility'] = source['Facility'].value
    if os.path.exists(rsyslog_conf_path):
        conf_path = oms_rsyslog_conf_path
    elif os.path.exists(syslog_ng_conf_path):
        conf_path = oms_syslog_ng_conf_path
    else:
        LG().Log('ERROR', 'Unable to find OMS config files.')
        raise Exception('Unable to find OMS config files.')
    LG().Log('INFO', 'Config file is ' + conf_path + '.')

    omsagent_dir = '/etc/opt/microsoft/omsagent/'
    multi_homed = os.path.isdir(omsagent_dir + WorkspaceID + '/conf')


def Set_Marshall(SyslogSource, WorkspaceID):
    if os.path.exists(sysklog_conf_path):
        LG().Log('ERROR', 'Sysklogd is unsupported.')
        return [0]
    init_vars(SyslogSource, WorkspaceID)
    retval = Set(SyslogSource, WorkspaceID)
    if retval is False:
        retval = [-1]
    else:
        retval = [0]
    return retval


def Test_Marshall(SyslogSource, WorkspaceID):
    if os.path.exists(sysklog_conf_path):
        LG().Log('ERROR', 'Sysklogd is unsupported.')
        return [0]
    init_vars(SyslogSource, WorkspaceID)
    return Test(SyslogSource, WorkspaceID)


def Get_Marshall(SyslogSource, WorkspaceID):
    if os.path.exists(sysklog_conf_path):
        LG().Log('ERROR', 'Sysklogd is unsupported.')
        return 0, {'SyslogSource':protocol.MI_InstanceA([])}
    arg_names = list(locals().keys())
    init_vars(SyslogSource, WorkspaceID)
    retval = 0
    NewSource = Get(SyslogSource, WorkspaceID)
    for source in NewSource:
        if source['Severities'] is not None:
            source['Severities'] = protocol.MI_StringA(source['Severities'])
        source['Facility'] = protocol.MI_String(source['Facility'])
    SyslogSource = protocol.MI_InstanceA(NewSource)
    WorkspaceID = protocol.MI_String(WorkspaceID)
    retd = {}
    ld = locals()
    for k in arg_names:
        retd[k] = ld[k]
    return retval, retd


def Set(SyslogSource, WorkspaceID):
    if Test(SyslogSource, WorkspaceID) == [0]:
        return [0]
    if conf_path == oms_syslog_ng_conf_path:
        ret = UpdateSyslogNGConf(SyslogSource, WorkspaceID)
    else:
        ret = UpdateSyslogConf(SyslogSource, WorkspaceID)
    if ret:
        ret = [0]
    else:
        ret = [-1]
    return ret


def Test(SyslogSource, WorkspaceID):
    if conf_path == oms_syslog_ng_conf_path:
        NewSource = ReadSyslogNGConf(SyslogSource, WorkspaceID)
    else:
        NewSource = ReadSyslogConf(SyslogSource, WorkspaceID)
    # TODO also figure out if I should be parsing the syslogconf any differently
    SyslogSource=sorted(SyslogSource, key=lambda k: k['Facility'])
    for d in SyslogSource:
        found = False
        if 'Severities' not in d.keys() or d['Severities'] is None or len(d['Severities']) is 0:
            d['Severities'] = ['none']  # redundant?
        d['Severities'].sort()
    NewSource=sorted(NewSource, key=lambda k: k['Facility'])
    for n in NewSource:
        n['Severities'].sort()
    if SyslogSource != NewSource:
        return [-1]
    return [0]


def Get(SyslogSource, WorkspaceID):
    if conf_path == oms_syslog_ng_conf_path:
        NewSource = ReadSyslogNGConf(SyslogSource, WorkspaceID)
    else:
        NewSource = ReadSyslogConf(SyslogSource, WorkspaceID)
    for d in NewSource:
        if d['Severities'] == ['none']:
            d['Severities'] = []
    return NewSource


def ParseSyslogConf(txt):
    facility_search = r'^(.*?)@.*?25224$'
    facility_re = re.compile(facility_search, re.M)
    return facility_re.findall(txt)


def ParseSyslogConfMultiHomed(txt, WorkspaceID):
    # For corner cases, we'll check that the file is of the format we expect
    header_str = '# OMS Syslog collection for workspace ' + WorkspaceID
    header_search = r'^' + header_str + '$'
    header_re = re.compile(header_search, re.M)
    mh_header = header_re.search(txt)

    if mh_header is None: # the expected multi-homing header was not found
        return ParseSyslogConf(txt)

    # Max number of facility/severity combos: 8 levels * 19 facilities = 152
    workspace_search = r'^' + header_str + '\n((.*@[0-9\.\:]*\n){1,160})'
    workspace_re = re.compile(workspace_search, re.M)
    workspace_facilities = workspace_re.search(txt)

    if workspace_facilities is None:
        return []

    facilities_str = workspace_facilities.group(1)
    facility_search = r'^(.*?)@[0-9\.\:]*$'
    facility_re = re.compile(facility_search, re.M)
    return facility_re.findall(facilities_str)


def ReadSyslogConf(SyslogSource, WorkspaceID):
    out = []
    txt = ''
    if len(SyslogSource) == 0:
        return out
    if not os.path.exists('/etc/rsyslog.d'):
        try:
            txt = codecs.open(rsyslog_conf_path, 'r', 'utf8').read()
            LG().Log('INFO', 'Successfully read ' + rsyslog_conf_path + '.')
        except:
            LG().Log('ERROR', 'Unable to read ' + rsyslog_conf_path + '.')
    else:
        src_conf_path = conf_path
        if os.path.exists(rsyslog_inc_conf_path):
            src_conf_path = rsyslog_inc_conf_path
        try:
            txt = codecs.open(src_conf_path, 'r', 'utf8').read()
            LG().Log('INFO', 'Successfully read ' + src_conf_path + '.')
        except:
            LG().Log('ERROR', 'Unable to read ' + src_conf_path + '.')
            return out

    if multi_homed:
        lines = ParseSyslogConfMultiHomed(txt, WorkspaceID)
    else:
        lines = ParseSyslogConf(txt)

    for line in lines:
        l = line.replace('=', '')
        l = l.replace('\t', '').split(';')
        sevs = []
        fac = l[0].split('.')[0]
        for sev in l:
            sevs.append(sev.split('.')[1])
        out.append({'Facility': fac, 'Severities': sevs})
    return out


def UpdateSyslogConf(SyslogSource, WorkspaceID):
    # TODO: Find my workspace ID in the conf file and ONLY replace that section of the conf in this method
    arg = ''
    if 'rsyslog' in conf_path:
        if os.path.exists('/etc/rsyslog.d'):
            txt = ''
        elif os.path.exists(rsyslog_conf_path):
            arg = '1'
            try:
                txt = codecs.open(rsyslog_conf_path, 'r', 'utf8').read()
                LG().Log(
                    'INFO', 'Successfully read ' + rsyslog_conf_path + '.')
            except:
                LG().Log('ERROR', 'Unable to read ' + rsyslog_conf_path + '.')

    # TODO HERE must figure out how to parse this
    # TODO Idea: If I just get this to take into account the workspace ID, I can find the section with just my workspace ID lines and replace only those.
    facility_search = r'(#facility.*?\n.*?25224\n)|(^[^#].*?25224\n)'
    facility_re = re.compile(facility_search, re.M)
    # This nexted for loop replaces every line that gives a facility, warning, and port
    for t in facility_re.findall(txt):
        for r in t:
            txt = txt.replace(r, '')

    # however, this for loop just appends my facility lines to the end of the file. I think I want to add them to the same section they were in before
    # TODO idea: save the entire text file in varZ
    #            Get a regex for the whole workspace-specific section in the file like I have in ParseSyslogConfMultiHomed - save this section as is in varA and make a copy in varB
    #            Extract the port used for this workspace from varB
    #            Run the above (or similar) for loop on varB to get rid of the previous conf
    #            Add each new facility/severity with the extracted port to the end of varB
    #            Replace the old section (varA) with the newly formed section (varB) in the whole conf file (varZ)
    #            Write the new complete conf file (varZ) to the configuration file
    for d in SyslogSource:
        facility_txt = '#facility = ' + d['Facility'] + '\n'
        for s in d['Severities']:
            facility_txt += d['Facility'] + '.=' + s + ';'
        facility_txt = facility_txt[0:-1] + '\t@127.0.0.1:25224\n'
        txt += facility_txt

    try:
        codecs.open(conf_path, 'w', 'utf8').write(txt)
        LG().Log(
            'INFO', 'Created omsagent rsyslog configuration at ' + conf_path + '.')
    except:
        LG().Log(
            'ERROR', 'Unable to create omsagent rsyslog configuration at ' + conf_path + '.')
        return False
    if os.system('sudo /opt/microsoft/omsconfig/Scripts/OMSRsyslog.post.sh ' + arg) == 0:
        LG().Log('INFO', 'Successfully executed OMSRsyslog.post.sh.')
    else:
        LG().Log('ERROR', 'Error executing OMSRsyslog.post.sh.')
        return False
    return True


def ReadSyslogNGConf(SyslogSource, WorkspaceID):
    #TODO
    out = []
    txt = ''
    try:
        txt = codecs.open(syslog_ng_conf_path, 'r', 'utf8').read()
        LG().Log('INFO', 'Successfully read ' + syslog_ng_conf_path + '.')
    except:
        LG().Log('ERROR', 'Unable to read ' + syslog_ng_conf_path + '.')
        return out
    facility_search = r'^filter f_(?P<facility>.*?)_oms.*?level\((?P<severities>.*?)\)'
    facility_re = re.compile(facility_search, re.M)
    for s in facility_re.findall(txt):
        sevs = []
        if len(s[1]):
            if ',' in s[1]:
                sevs = s[1].split(',')
            else:
                sevs.append(s[1])
        out.append({'Facility': s[0], 'Severities': sevs})
    return out


def UpdateSyslogNGConf(SyslogSource, WorkspaceID):
    #TODO make sure that facility is no longer determined by the filter/destination labels
    txt = ''
    try:
        txt = codecs.open(syslog_ng_conf_path, 'r', 'utf8').read()
        LG().Log('INFO', 'Successfully read ' + syslog_ng_conf_path + '.')
    except:
        LG().Log('ERROR', 'Unable to read ' + syslog_ng_conf_path + '.')
        return False
    facility_search = r'(\n+)?(#OMS_Destination.*?25224.*?\n)?(\n)?(#OMS_facility.*?filter.*?_oms.*?log.*destination.*?\n)'
    facility_re = re.compile(facility_search, re.M | re.S)
    txt = facility_re.sub('', txt)
    txt += '\n\n#OMS_Destination\ndestination d_oms { udp("127.0.0.1" port(25224)); };\n'
    for d in SyslogSource:
        if 'Severities' not in d.keys() or d['Severities'] is None or len(d['Severities']) is 0:
            facility_txt = ''
        else:
            facility_txt = '\n#OMS_facility = ' + d['Facility'] + '\n'
            sevs = reduce(lambda x, y: x + ',' + y, d['Severities'])
            facility_txt += 'filter f_' + \
                d['Facility'] + \
                '_oms { level(' + sevs + ') and facility(' + d[
                    'Facility'] + '); };\n'
            facility_txt += 'log { source(src); filter(f_' + d[
                'Facility'] + '_oms); destination(d_oms); };\n'
            txt += facility_txt
    try:
        codecs.open(conf_path, 'w', 'utf8').write(txt)
        LG().Log(
            'INFO', 'Created omsagent syslog-ng configuration at ' + conf_path + '.')
    except:
        LG().Log(
            'ERROR', 'Unable to create omsagent syslog-ng configuration at ' + conf_path + '.')
        return False
    if os.system('sudo /opt/microsoft/omsconfig/Scripts/OMSSyslog-ng.post.sh') == 0:
        LG().Log('INFO', 'Successfully executed OMSSyslog-ng.post.sh.')
    else:
        LG().Log('ERROR', 'Error executing OMSSyslog-ng.post.sh.')
        return False
    return True
