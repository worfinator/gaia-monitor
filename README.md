# gaia-monitor

Gaia Monitor - Enables the extraction of CheckPoint information from the default Gaia web interface to be index into Elastic Search for monitoring and alerting.

## Requirements

- Ansible Tower

- Elastic Search cluster

- CheckPoint Gaia account

- Firewall access enabled to the Gaia web interface

- Python modules
  - requests
  - json
  - hjson
  - urllib3
  - Elasticsearch
  - ssl
  - requests

## Role Variables

```yaml
host: cp-01 #CheckPoint Device to monitor

domain: .mydomain.com #option domain to add to host if required to resolve host

method: All #Gaia Endpoint data to retrieve (All, hostname, overview,backup, operation, monitor, blades-summary)

username: monitor_account #Gaia username

password: 12345 #Gaia password

es_host: es.mydomain.com #Elastic Search host

es_port: 9300 #Elastic Search port

es_username: elastic #Elastic Search username

es_password: 12345 #Elastic Search password/secret

es_index: gaia-monitior #Elastic Search index

ca_path: /etc/ssl/certs/mydomain.pem #Certificate of Authority .pem file
```

## Example Playbook

Presuming that you are using this role within Ansible Tower with an inventory group named CHECKPOINT-Firewalls, Replace CP-01 and CP-02 with valid host names if you wish to run this playbook standalone outside of Tower.

```yaml
- name: CheckPoint Blades Checker

  hosts: localhost

  vars:
  CheckPoints: - CP-01 - CP-02
  domain: .mydomain.com #option domain to add to host if required to resolve host

  tasks:

  - name: Set hosts
    set_fact:
    CheckPoints: "{{ groups['CHECKPOINT-Firewalls'] }}"
    when: groups['CHECKPOINT-Firewalls'] is defined

  - name: CheckPoints we will be querying
    debug:
    var: CheckPoints

  - include_role: name=gaia-monitor
    with_items: "{{ CheckPoints }}"
    loop_control:
    loop_var: checkpoint
```

## License

GPL-2.0-or-later

## Author Information

For feedback and comments please contact me via:

mark.baldwin.nz@gmail.com
