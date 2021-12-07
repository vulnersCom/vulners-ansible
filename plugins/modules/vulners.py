#!/usr/bin/python
# (c) 2017, Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# most of it copied from AWX's scan_packages module

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
    name: vulners
    short_description: Check target host for vulnerable packages
    description: >
         This plugins allows you to check check whether you have vulnerable packages installed on the target system.
          It requires a valid vulners API key to run: you can specify it as a CLI argument or store it in a file and specify its name as CLI argument.
          The resukts are stored as json and html files under /tmp directory.
    author: gmedian
    options:
        vulners_api_key:
            description: You key for Vulners API (obtain one at https://vulners.com/)
            vars:
              - name: api_key
        vulners_api_key_file:
            description: Location of your file with your key for Vulners API (obtain one at https://vulners.com/)
            vars:
              - name: api_key_file
"""