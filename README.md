# Role Name

Gaia Monitor - Enables the loging of CheckPoint information to Elastic Search for monitoring and alerting.

## Requirements

- Elastic Search cluster

- Python modules
  - requests
  - json
  - hjson
  - urllib3
  - Elasticsearch
  - ssl
  - requests

## Role Variables

    host: CheckPoint Device to monitor

    method: Gaia Endpoint data to retrieve (All, hostname, overview,backup, operation, monitor, blades-summary)

    username:  Gaia username

    password: Gaia password

    es_host: Elastic Search host

    es_port: Elastic Search port

    es_username: Elastic Search username

    es_password: Elastic Search password/secret

    es_index: Elastic Search index

    ca_path: Certificate of Authority .pem file

## Example Playbook

Presuming that you are using this role within Ansible Tower with an inventory group named CHECKPOINT-Firewalls, Replace CP-01 and CP-02 with valid host names if you wish to run this playbook standalone outside of Tower.

- name: CheckPoint Blades Checker

  hosts: localhost

  vars:
  CheckPoints: - CP-01 - CP-02

  tasks:

  - name: Set hosts
    set_fact:
    CheckPoints: "{{ groups['CHECKPOINT-Firewalls'] }}"
    when: groups['CHECKPOINT-Firewalls'] is defined

  - name: CheckPoints we will be querying
    debug:
    var: CheckPoints

  - include_role: name=gaia-monitoring
    with_items: "{{ CheckPoints }}"  
    loop_control:
    loop_var: checkpoint

## License

BSD

## Author Information

For feedback and comments please contact me via:

mark.baldwin.nz@gmail.com
