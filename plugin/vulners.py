#!/usr/bin/python
# Make coding more python3-ish, this is required for contributions to Ansible
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import json
import os
import re
from time import sleep

from ansible.errors import AnsibleError
from ansible.module_utils.common.text.converters import to_native
from ansible.plugins.action import ActionBase
from requests import post

DOCUMENTATION = """
    name: vulners
    short_description: Check target host for vulnerable packages
    description:
        - This plugins allows you to check check whether you have vulnerable packages installed on the target system.
    author: gmedian
    options:
        vulners_api_key:
            description: You key for Vulners API (obtain one at https://vulners.com/)
            ini:
              - section: vulners_section
                key: vulners_api_key
            vars:
              - name: vulners_api_key
            env:
              - name: VULNERS_API_KEY
        vulners_full_description:
            description: Show full vulnerability description 
            ini:
              - section: vulners_section
                key: vulners_full_description
            vars:
              - name: vulners_full_description
            env:
              - name: VULNERS_FULL_DESCRIPTION
"""

class ActionModule(ActionBase):
    DEFAULT_HEADERS = {
        'User-agent': 'Vulners-Ansible-scan/0.0.1',
        'Content-type': 'application/json'
    }

    VULNERS_LINKS = {
        'pkgChecker': 'https://vulners.com/api/v3/audit/audit/',
        'cveChecker': 'https://vulners.com/api/v3/search/id/'
    }

    KEY_NAME = 'api_key'
    KEY_FILE_NAME = 'api_key_file'

    DEFAULT_FILE_NAME = '.vulners.ansible.env'

    RESULT_FILE_NAME = '/tmp/vulners_ansible_result.json'

    def run(self, tmp=None, task_vars=None):

        #if self.KEY_NAME not in self._task.args:
        #    if self.KEY_FILE_NAME not in self._task.args:
        #        return {"failed": True, "msg": "One of '%s' or '%s' arguments is required" %(self.KEY_NAME, self.KEY_FILE_NAME)}
        

        # Need to pop value, otherwise further module executions would fail (seemingly of unexpected arg)
        self.key = self.get_key()

        if not self.key:
            # It means no option for key was givena nad no default file was found
            return {"failed": True, "msg": "No API key was found"}

        #return dict(ansible_facts=dict(result={"done":self._task.args, "vars": self._task.vars}))

        super(ActionModule, self).run(tmp, task_vars)
        module_return = self._execute_module(module_name='package_facts', tmp=tmp, task_vars=task_vars)
        ret = dict()

        packages = list()
        bad = list()

        for name, pkg_list in module_return['ansible_facts']['packages'].items():
            try:
                source = pkg_list[0].get('source')
                if source == 'rpm':
                    packages += ['%(name)s-%(version)s-%(release)s.%(arch)s'%k for k in pkg_list]
                elif source == 'apt':
                    packages += ['%(name)s %(version)s %(arch)s'%k for k in pkg_list]
                elif source == 'apk':
                    packages += ['%(name)s-%(version)s-%(release)s x86_64 {%(name)s} (GPL-2.0-only) [installed]'%k for k in pkg_list]
                else:
                    self.error(f'Unknown source {source}')
            except Exception as e:
                self.error(e)
                bad.append(name)

        hostname, osname, osversion, osdversion = self.get_os_info(tmp=tmp, task_vars=task_vars)

        if osname == 'Alpine': #TODO Dirty
            osversion = re.match('\d+\.\d+', osdversion).group(0)

        if not len(packages):
            self.error(f'No packages found for {hostname} - {osname} v.{osversion}')
            return dict(ansible_facts={"done": "ERROR"})

        vuln_packages = self.get_vulnerable_packages(hostname, osname, osversion, packages)

        vuln_details = self.get_cve_info(vuln_packages.get('all_cve'))

        result = self.write_results(hostname, vuln_packages, vuln_details)

        return dict(ansible_facts=dict(result={"done":"OK", "result": result}))

    def write_results(self, hostname, vuln_packages, vuln_details):
        result = {
            'hosts': {},
            'cve_list': {}
        }
        if os.path.isfile(self.RESULT_FILE_NAME):
            with open(self.RESULT_FILE_NAME, "r") as ifile:
                result = json.load(ifile)

        with open(self.RESULT_FILE_NAME, "w") as ofile:
            result['hosts'][hostname] = vuln_packages
            result['cve_list'].update(vuln_details)
            json.dump(result, ofile, indent=2)

        self.write_html(result)

        return result

    def write_html(self, result):
        with open("/tmp/vulners_ansible_result.html", "w") as ofile:
            b64 = base64.b64encode(json.dumps(result, indent=2).encode('utf-8')).decode('utf-8')
            ofile.write(f'''<html>
                <body><pre><code>{b64}</code></pre></body>
            </html>''')

    def get_vulnerable_packages(self, hostname, osname, osversion, packages):
        payload = {
            'os': osname,
            'version': osversion,
            'package': packages,
            'apiKey': self.get_key()
        }

        self.log("Running scan of %s with version %s" %(osname, osversion))
        res = post(self.VULNERS_LINKS.get('pkgChecker'), headers=self.DEFAULT_HEADERS, data=json.dumps(payload))

        status = res.json().get('result')
        data = res.json().get('data')

        if status == 'error':
            # For example if license expired
            self.error(f'Scan failed for {hostname} - {osname} v.{osversion} \n {data}')
            raise AnsibleError(f'Scan failed for {hostname} - {osname} v.{osversion} \n { to_native(data)}')

        result = dict()
        all_cve = list()

        if res.status_code == 200 and status == "OK":
            for pkg, info in data.get('packages', {}).items():
                cvelist = []
                for vuln_name, desc in info.items():
                    cvelist.append(sum(map(lambda x: x.get("cvelist", []), desc), []))
                cvelist = list(set(sum(cvelist, [])))
                if len(cvelist):
                    result[pkg] = {"cve": cvelist}
                    all_cve += cvelist
            result['all_cve'] = all_cve

        return result

    # TODO[gmedian]: pop rest of args not ot fail further execution
    def get_key(self):
        if self.KEY_NAME in self._task.args:
            self._task.args.pop(self.KEY_FILE_NAME, None)
            return self._task.args.pop(self.KEY_NAME)

        filename = self._task.args.pop(self.KEY_FILE_NAME, self.DEFAULT_FILE_NAME)

        if os.path.isfile(filename):
            with open(filename, 'r') as ifile:
                return ifile.read().strip('\n \t')

        return None 

    def get_os_info(self, tmp=None, task_vars=None):
        module_return = self._execute_module(module_name='setup', tmp=tmp, task_vars=task_vars)
        with open('/tmp/os_info.txt', 'w') as ofile:
            json.dump(module_return, ofile, indent=2)
        return module_return['ansible_facts'].get('ansible_hostname',''), module_return['ansible_facts'].get('ansible_distribution',''), module_return['ansible_facts'].get('ansible_distribution_major_version',''), module_return['ansible_facts'].get('ansible_distribution_version','')

    def log(self, msg):
        print(msg)

    def error(self, msg):
        print(f'\033[91m[ERROR] - {msg}')

    def get_cve_info(self, all_cve=list()):
        payload_2 = {
            'id': all_cve,
            'apiKey': self.get_key()
        }
        res = post(self.VULNERS_LINKS.get('cveChecker'), headers=self.DEFAULT_HEADERS, data=json.dumps(payload_2))
        cve_info = dict()
        if res.status_code == 200 and res.json().get('result') == "OK":
            for cve, info in res.json()['data'].get('documents', {}).items():
                self.log(info)
                score = info.get('cvss', {}).get('score')
                vulnersScore = info.get('enchantments', {}).get('vulnersScore')
                title = info.get('title')
                description = info.get('description')
                severity = info.get('cvss2', {}).get('severity')
                cve_info[cve] = {
                    "score": score,
                    "vulnersScore": vulnersScore,
                    "title": title,
                    "description": description,
                    "severityText": severity
                }
            return cve_info
