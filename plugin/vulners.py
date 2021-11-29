#!/usr/bin/python
# Make coding more python3-ish, this is required for contributions to Ansible
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import os
from time import sleep

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
                # TODO GMedian - release is appeared only for RPM based package manager
                # (https://docs.ansible.com/ansible/latest/collections/ansible/builtin/package_facts_module.html#return-ansible_facts/packages)

                source = pkg_list[0].get('source')
                if source == 'rpm':
                    packages += ['%(name)s-%(version)s-%(release)s.%(arch)s'%k for k in pkg_list]
                elif source == 'apt':
                    packages += ['%(name)s %(version)s %(arch)s'%k for k in pkg_list]
                elif source == 'apk':
                    packages += ['%(name)s-%(version)s-%(release)s'%k for k in pkg_list]
                else:
                    self.error(f'Unknown source {source}')
            except Exception as e:
                self.error(e)
                bad.append(name)

        hostname, osname, osversion = self.get_os_info(tmp=tmp, task_vars=task_vars)

        if not len(packages):
            self.error(f'No packages found for {hostname} - {osname} v.{osversion}')
            return dict(ansible_facts={})

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
            return dict(ansible_facts=data)

        result = dict()
        all_cve = list()

        self.log(f'[INFO] {status} - {data}')
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

        vulns = self.get_cve_info(result.get('all_cve'))

        r_old = dict()
        if os.path.isfile(self.RESULT_FILE_NAME):
            with open(self.RESULT_FILE_NAME, "r") as ifile:
                r_old = json.load(ifile)
        
        with open(self.RESULT_FILE_NAME, "w") as ofile:
            r_old[hostname] = result
            json.dump(r_old, ofile, indent=2)

        with open("/tmp/txt_vuln.txt", "w") as ofile:
            ofile.write(json.dumps(vulns, indent=2))


        return dict(ansible_facts=dict(result={"done":"OK"}))

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
        return module_return['ansible_facts'].get('ansible_hostname',''), module_return['ansible_facts'].get('ansible_distribution',''), module_return['ansible_facts'].get('ansible_distribution_major_version','')

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
                score = info.get('cvss', {}).get('score')
                vulnersScore = info.get('enchantments', {}).get('vulnersScore')
                title = info.get('title')
                severity = info.get('cvss2', {}).get('severity')
                cve_info[cve] = {
                    "score": score,
                    "vulnersScore": vulnersScore,
                    "title": title,
                    "severityText": severity
                }
            return cve_info
