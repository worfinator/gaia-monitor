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

parameters: elastic search or logstash datastore parameters:


#Elastic search
parameters:
  type: elastic
  host: es.mydomain.com #Elastic Search host
  port: 9300 #Elastic Search port
  username: elastic #Elastic Search username
  password: 12345 #Elastic Search password/secret
  index: gaia-monitior #Elastic Search index
  ca_path: /etc/ssl/certs/mydomain.pem #Certificate of Authority .pem file

#Logstash
parameters:
  type: logstash
  host: ls.mydomain.com #Logstash host
  port: 5959 #Logstash port
  protocol: tcp #Logstash protocol either tcp or udp
  version: 1 #Logstash logger version

```

## Example Playbook

Presuming that you are using this role within Ansible Tower with an inventory group named CHECKPOINT-Firewalls, Replace CP-01 and CP-02 with valid host names if you wish to run this playbook standalone outside of Tower.

```yaml
- name: CheckPoint Blades Checker

  hosts: localhost

  vars:
  CheckPoints:
    - CP-01
    - CP-02

  gaia:
    username: myuser
    password: mypassword
    domain: mydomain.com #option domain to add to host if required to resolve host
    method: All

  data_store:
    type: elastic
    host: elasticsearch.mydomain.com
    port: 9300
    username: elasticUser
    password: elasticPassword
    index: my-index-of-something
    ca_path: /etc/ssl/certs/mydomain.pem

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
        loop_var: gaia_host
```

## License

GPL-2.0-or-later

## Author Information

For feedback and comments please contact me via:

mark.baldwin.nz@gmail.com
