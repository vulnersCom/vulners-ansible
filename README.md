# Vulners Ansible Plugin

## Introduction

This repo hosts the `vulners` Ansible Collection.


### About vulners

Vulners is a vulnerability database and vulnerability assessment and management system. 

## Usage

```bash
ansible all -m vulners
```

## DEV Installation


### MacOS
Install Ansible locally
```
brew install ansible
```
Add list of hosts that need to be monitored
```bash
bash-3.2$ vi /etc/ansible/hosts

10.4.1.3
10.5.1.2
10.4.1.1
webgoat.io:2222 ansible_user=test
127.0.0.1:2223 ansible_user=test
```
Link vulners plugin to local Ansible modules
```bash
ln -s ./plugin/vulners.py ~/.ansible/plugins/modules/vulners.py
```



## License

GNU General Public License v3.0 or later

See [LICENSE](LICENSE) to see the full text.