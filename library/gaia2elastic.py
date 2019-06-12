import datetime
import time
import requests
import json
import hjson
import urllib3
from elasticsearch import Elasticsearch
from ssl import create_default_context
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from ansible.module_utils.basic import AnsibleModule

# arguments for the module:
fields = {
    "host": {
        "required": True,
        "type": "str"
    },
    "method": {
        "type": "str",
        "default": "All"
    },
    "username": {
        "required": True,
        "type": "str"
    },
    "password": {
        "required": False,
        "type": "str",
        "no_log": True
    },
    "es_host": {
        "required": True,
        "type": "str"
    },
    "es_port": {
        "required": True,
        "type": "str"
    },
    "es_username": {
        "required": True,
        "type": "str"
    },
    "es_password": {
        "required": True,
        "type": "str",
        "no_log": True
    },
    "es_index": {
        "required": True,
        "type": "str"
    },
    "ca_path": {
        "required": True,
        "type": "str"
    }
}

module = AnsibleModule(argument_spec=fields, supports_check_mode=True)

es = {}

session = {
    'host': '',
    'basepath': '/cgi-bin/',
    'sid': '',
    'epoch': '',
    'cookie': '',
    'alive': False,
    'message': ''
}

methods = {
    'hostname': '',
    'overview': '',
    'backup': 'operation=query-backup-progress',
    'monitor': '',
    'blades-summary': ''
    #'interfaces': 'overview_page=t'

}



urllib3.disable_warnings()

def setElasticSearch(es_host, es_port, es_username, es_password, ca_path):
    context = create_default_context(cafile=ca_path)

    es_object = Elasticsearch(
        [es_host],
        http_auth=(es_username, es_password),
        scheme="https",
        port=es_port,
        ssl_context=context,
    )

    return es_object

def requests_retry_session(
    retries=1,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504),
    session=None
):
    session = session or requests.Session()
    session.trust_env = False
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def setSession(cookie):
    now = datetime.datetime.utcnow()
    session['date'] = now.strftime('%Y-%m-%d')
    session['sid'] = cookie.split('Session=')[1]
    session['epoch'] = int(time.time())
    session['alive'] = True
    session['cookie'] = cookie

def setBasePath(path):
    session['basepath'] = path

def login(username, password):
    headers = {
        'Host': session['host'],
        'Origin': "https://"+session['host'],
        'Referer': "https://"+session['host']+"/",
        'Connection': "keep-alive",
        'Content-Length': "42",
        'Pragma': "no-cache",
        'Cache-Control': "no-cache",
        'Upgrade-Insecure-Requests': "1",
        'Content-Type': "application/x-www-form-urlencoded",
        'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Safari/537.36",
        'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
        'Accept-Encoding': "gzip, deflate, br",
        'Accept-Language': "en-NZ,en-GB;q=0.9,en-US;q=0.8,en;q=0.7",
        'Cookie': "Session=Login"
    }
    
    try:
        url = 'https://'+session['host']+session['basepath']+'home.tcl'
        payload = 'userName=' + username + '&userPass=' + password
        response = requests_retry_session().request("POST", url, data=payload, headers=headers, verify=False)

        #print(response.headers)
        #print(response.text)

        if response.status_code == 200 and response.text.find('location.href = "') > 0:
            setBasePath('/' + response.text.split('location.href = "')[1].split('"')[0].split('/')[1] + session['basepath'])
            setSession(response.headers['Set-Cookie'])
        else:
            session['message'] = 'Error connecting to host: ' + session['host']
    except:
       session['alive'] = False
       session['message'] = 'No response from host: ' + session['host']

def constructURL(method):
    url = 'https://'+session['host']+session['basepath']+method+'.tcl'
    
    return url

def constructParams(method):
    querystring = {
        "_dc": session['epoch']
    }
    params = methods[method]

    if len(params):
        params.split("=")
        querystring[params[0]] = params[1]

    return querystring

def callAPI(method):
    headers = {
        'User-Agent': "PostmanRuntime/7.13.0",
        'Accept': "*/*",
        'accept-encoding': "gzip, deflate",
        'Connection': "keep-alive"
    }
    
    headers['Host'] = session['host']
    headers['cookie'] = session['cookie']
    
    url = constructURL(method)
    querystring = constructParams(method)

    data = {}
  
    try:
        response = requests_retry_session().request("GET", url, headers=headers, params=querystring, verify=False)

        #print(url)
        #print(headers)
        #print(response.text)

        if response.status_code == 200 and session['alive'] == True:
            data = filterData(method, hjson.loads(response.text))
        else:
            session['message'] = 'Error connecting to host: ' + session['host']
    except:
        session['alive'] = False
        session['message'] = 'No response from host: ' + session['host']

    return data

def filterData(method, data):
    if method == 'blades-summary':
        data = bladeFilter(data)

    return data

def bladeFilter(data):
    newdata = {}
    blades = {}
    
    newdata['data'] = {}

    for blade in data['data']['blades']:
        tmpBlade = {}
        tmpChart = {}
        
        tmpBlade['is_enabled'] = blade['is_enabled']
        
        for k,v in blade['fields'].iteritems():
            if k == 'Last update':
                tmpBlade['update_status'] = v.split("Database version: ")[0]
                tmpBlade['update_version'] = v.split("Database version: ")[1].split('.')[0]
                tmpBlade['update_timestamp'] = v.split("Package date: ")[1].split(' .')[0]

            else:
                tmpBlade[k.replace(" ", "_")] = v

        for chart in blade['charts']:
            for k,v in chart.iteritems():
                tmpChart[k.replace(" ", "_")] = v

            tmpBlade[chart['title'].replace(" ", "_")] = tmpChart

        blades[blade['name'].replace(" ", "_")] = tmpBlade

    newdata['data'] = blades

    return newdata

def getData(method):
    data = {}

    # Bundle all info together
    if method == 'All':
        for k,v in methods.iteritems():
            json = callAPI(method=k)
            if 'data' in json:
                data[k] = json['data']
          
    else:
        json = callAPI(method=method)
        if 'data' in json:
            data = json['data']

    return data

def index2Elastic(es, index, data, method):
    esindex = index + '-' + session['date'] 
    response = es.index(index=esindex, doc_type=method, body=data)

    return response

def main(host, username, password, method, es_host, es_port, es_username, es_password, es_index, ca_path):
    session['host'] = host
    data = {}
    response = {}
    
    es = setElasticSearch(es_host, es_port, es_username, es_password, ca_path)

    login(username=username, password=password)
    
    if session['alive'] == True:
        data = getData(method)
        data['host'] = host
        data['@timestamp'] = datetime.datetime.utcnow()

        response = index2Elastic(es=es, index=es_index, data=data, method=method)
    else:

        response = session['message']
    
    module.exit_json(changed=False, ansible_module_results=response)

# Get the show on the road
if __name__ == '__main__':
    main(
        host=module.params['host'], 
        method=module.params['method'], 
        username=module.params['username'], 
        password=module.params['password'],
        es_host=module.params['es_host'],
        es_port=module.params['es_port'],
        es_username=module.params['es_username'],
        es_password=module.params['es_password'],
        es_index=module.params['es_index'],
        ca_path=module.params['ca_path']
    )
