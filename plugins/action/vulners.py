#!/usr/bin/python
# Make coding more python3-ish, this is required for contributions to Ansible
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import base64
import json
import os
import re

from ansible.errors import AnsibleError
from ansible.module_utils.common.text.converters import to_native
from ansible.plugins.action import ActionBase
from requests import post


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
    RESULT_HTML_FILE_NAME = '/tmp/vulners_ansible_result.html'

    def run(self, tmp=None, task_vars=None):
        # Need to pop value, otherwise further module executions would fail (seemingly of unexpected arg)
        self.key = self.get_key()

        if not self.key:
            # It means no option for key was givena nad no default file was found
            return {"failed": True, "msg": "No API key was found"}

        super(ActionModule, self).run(tmp, task_vars)
        module_return = self._execute_module(module_name='package_facts', tmp=tmp, task_vars=task_vars)

        packages = list()

        for name, pkg_list in module_return['ansible_facts']['packages'].items():
            try:
                source = pkg_list[0].get('source')
                if source == 'rpm':
                    packages += ['%(name)s-%(version)s-%(release)s.%(arch)s' % k for k in pkg_list]
                elif source == 'apt':
                    packages += ['%(name)s %(version)s %(arch)s' % k for k in pkg_list]
                elif source == 'apk':
                    packages += ['%(name)s-%(version)s-%(release)s x86_64 {%(name)s} (GPL-2.0-only) [installed]' % k for k in pkg_list]
                else:
                    self.error(f'Unknown source {source}')
            except Exception as e:
                self.error(e)

        hostname, osname, osversion, osdversion, address = self.get_os_info(tmp=tmp, task_vars=task_vars)

        if osname == 'Alpine':  # TODO Dirty
            osversion = re.match(r'\d+\.\d+', osdversion).group(0)

        if not len(packages):
            self.error(f'No packages found for {hostname} - {osname} v.{osversion}')
            return dict(ansible_facts={"done": "ERROR"})

        vuln_packages = self.get_vulnerable_packages(hostname, osname, osversion, packages)

        vuln_details = self.get_cve_info(vuln_packages.get('all_cve'))

        self.write_results(hostname, address, vuln_packages, vuln_details)

        return dict(ansible_facts=dict(result={"done": "OK", "result": {"JSON_FILE": self.RESULT_FILE_NAME, "HTML_FILE": self.RESULT_HTML_FILE_NAME}}))

    def write_results(self, hostname, address, vuln_packages, vuln_details):
        result = {
            'hosts': {},
            'cve_list': {}
        }
        if os.path.isfile(self.RESULT_FILE_NAME):
            with open(self.RESULT_FILE_NAME, "r") as ifile:
                result = json.load(ifile)

        with open(self.RESULT_FILE_NAME, "w") as ofile:
            result['hosts'][address] = {
                'ip': address,
                'hostname': hostname,
                'packages': vuln_packages
            }
            result['cve_list'].update(vuln_details)
            json.dump(result, ofile, indent=2)

        self.write_html(result)

        return result

    def write_html(self, result):
        with open(self.RESULT_HTML_FILE_NAME, "w") as ofile:
            b64 = base64.b64encode(json.dumps(result, indent=2).encode('utf-8')).decode('utf-8')
            ofile.write(f'''<html>
                <head>
                    <meta name='viewport' content='width=900'><title>Vulnerability Inventory</title>
                    <style>code{{display:none}}body{{font-family:monospace;padding:16px;margin:0}}th{{text-align:left}}td{{vertical-align:top;border:solid 1px #fff;padding:4px}}a{{color:#f60}}.cve{{width:120px;min-width:120px}}.package{{width:200px;min-width:200px}}.score{{min-width:40px}}.table-line{{border-top:1px solid #d3d3d3}}</style>
                </head>
                <body><pre><code style="display:none;">{b64}</code></pre><div id='root'></div></body>
                <script>let hosts={{}},cveList={{}};const parse=()=>{{const e=JSON.parse(atob(document.querySelector("code").innerText));hosts=e.hosts,cveList=e.cve_list,render()}},render=()=>{{const e=Object.keys(hosts).map((e=>getHost(hosts[e],cveList))),t=document.getElementById("root");t.innerHTML=e,document.body.appendChild(t)}},getHost=(e,t)=>{{const n=esc(e.ip+" - "+e.hostname);return`<div>\n <h2>\n ${{n}}\n </h2>\n <table>\n <tr>\n <th>Package</td>\n <th>Vulnerabilities</td>\n </tr>\n ${{Object.keys(e.packages).filter((e=>"all_cve"!==e)).map((s=>getPackage(n,s,e.packages[s].cve,t))).join(" ")}}\n </table>\n </div>`}},getPackage=(e,t,n,s)=>`<tr class='table-line'>\n <td class='table-line package'>${{esc(t)}}</td>\n <td class='table-line'>\n <table>\n <tbody>\n ${{n.sort(((e,t)=>s[t].score-s[e].score)).map((e=>getVulnerability(e,s[e]))).join(" ")}}\n </tbody>\n </table>\n </td>\n </tr>`,getVulnerability=(e,t)=>{{const n=t.score||t.vulnersScore,s=getColor(n);return`\n <tr>\n <td class='cve'><a href='https://vulners.com/cve/${{esc(e)}}' target='_blank' rel='noreferrer noopener'>${{esc(e)}}</a></td>\n <td class='score' style='color:${{s}}'>${{esc(t.severityText)}}</td>\n <td class='score' style='color:${{s}}'>${{n}}</td>\n <td>${{esc(t.title===e?t.description:t.title)}}</td>\n </tr>`}},esc=e=>e.replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;"),COLORS=["#00c400","#00e020","#00f000","#d1ff00","#ffe000","#ffcc00","#ffbc10","#ff9c20","#ff8000","#ff0000","#ff0000"],getColor=e=>COLORS[parseInt(e||0)];document.addEventListener("DOMContentLoaded",parse);</script>
            </html>''')

    def get_vulnerable_packages(self, hostname, osname, osversion, packages):
        payload = {
            'os': osname,
            'version': osversion,
            'package': packages,
            'apiKey': self.key
        }

        self.log("Running scan of %s with version %s" % (osname, osversion))
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

    # TODO[gmedian]: pop rest of args not to fail further execution
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
        return module_return['ansible_facts'].get('ansible_hostname', ''), \
               module_return['ansible_facts'].get('ansible_distribution', ''), \
               module_return['ansible_facts'].get('ansible_distribution_major_version', ''), \
               module_return['ansible_facts'].get('ansible_distribution_version', ''), \
               module_return['ansible_facts'].get('ansible_default_ipv4', {}).get('address')

    def log(self, msg):
        print(msg)

    def error(self, msg):
        print(f'\033[91m[ERROR] - {msg}')

    def get_cve_info(self, all_cve=list()):
        payload_2 = {
            'id': all_cve,
            'apiKey': self.key
        }
        res = post(self.VULNERS_LINKS.get('cveChecker'), headers=self.DEFAULT_HEADERS, data=json.dumps(payload_2))
        cve_info = dict()
        if res.status_code == 200 and res.json().get('result') == "OK":
            for cve, info in res.json()['data'].get('documents', {}).items():
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
