import datetime
import time
import requests
import json
import hjson
import urllib3
import base64
from elasticsearch import Elasticsearch
from ssl import create_default_context
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from ansible.module_utils.basic import AnsibleModule

# arguments for the module:
fields = {
    "gaia": {},
    "datastore": {}
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
    # 'interfaces': 'overview_page=t'

}


urllib3.disable_warnings()


def setLogstash(host, port, username, password, version, ssl):
    ls_object = {
        'headers': {
            'Host': host + ':' + port,
            'Content-Type': "application/json",
            'User-Agent': "Python/Logger",
            'Accept': "*/*",
            'Accept-Encoding': "gzip, deflate"
        }
    }

    protocol = 'http'
    if ssl:
        protocol = 'https'

    ls_object['url'] = protocol + '://' + host + ':' + port

    if len(username) and len(password):
        auth = username + ':' + password
        auth = 'Basic ' + base64.b64encode(auth)
        ls_object['headers']['Authorization'] = auth
    
    return ls_object


def setElasticSearch(host, port, username, password, ca_path):
    context = create_default_context(cafile=ca_path)

    es_object = Elasticsearch(
        [host],
        http_auth=(username, password),
        scheme="https",
        port=int(port),
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
        response = requests_retry_session().request(
            "POST", url, data=payload, headers=headers, verify=False)

        # print(response.headers)
        # print(response.text)

        if response.status_code == 200 and response.text.find('location.href = "') > 0:
            setBasePath('/' + response.text.split('location.href = "')
                        [1].split('"')[0].split('/')[1] + session['basepath'])
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
        response = requests_retry_session().request(
            "GET", url, headers=headers, params=querystring, verify=False)

        # print(url)
        # print(headers)
        # print(response.text)

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

        for k, v in blade['fields'].iteritems():
            if k == 'Last update':
                tmpBlade['update_status'] = v.split("Database version: ")[0]
                tmpBlade['update_version'] = v.split(
                    "Database version: ")[1].split('.')[0]
                tmpBlade['update_timestamp'] = v.split(
                    "Package date: ")[1].split(' .')[0]

            else:
                tmpBlade[k.replace(" ", "_")] = v

        for chart in blade['charts']:
            for k, v in chart.iteritems():
                tmpChart[k.replace(" ", "_")] = v

            tmpBlade[chart['title'].replace(" ", "_")] = tmpChart

        blades[blade['name'].replace(" ", "_")] = tmpBlade

    newdata['data'] = blades

    return newdata


def getData(method):
    data = {}

    # Bundle all info together
    if method == 'All':
        for k, v in methods.iteritems():
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


def index2logstash(ls, data, method):
    output = {
        "status": 500,
        "message": "Unknown error while communicating to Logstash endpoint"
    }

    try:
        response = requests_retry_session().request(
                "PUT", ls['url'], data=json.dumps(data), headers=ls['headers'], verify=False)
       
        output['status'] = response.status_code

        if response.status_code == 200:
           output['message'] = 'Data successfully submitted to Logstash endpoint'

        if response.status_code == 401:
           output['message'] = 'Authorisation to Logstash endpoint failed'
      
    except: 
        output = {
            "status": 404,
            "message":"Error connecting to Logstash endpoint, check connection"
        }

    return output

def cleanParams(parameters):
    parameters = parameters.replace("None", "null")
    parameters = parameters.replace("'", '"')
    # The following replace method must be the last replace option!!!
    # This is intended for running run-script API command in CLISH mode, where the "'" character is required inside the script parameter.
    # Example: "clish -c 'show core-dump status'"
    # For such case, the YML must be in the following format: 'clish -c \"show core-dump status\"'
    parameters = parameters.replace("\\\\\"", "'")
    parameters = parameters.replace("True", "true")
    parameters = parameters.replace("False", "false")
    # Finally, parse to JSON
    parameters = json.loads(parameters)

    return parameters

def main():
    data = {}
    response = {}

    gaia = module.params.get('gaia')
    datastore = module.params.get('datastore')

    if gaia:
        gaia = cleanParams(gaia)
        gaia['host'] = gaia.get('host')
        gaia['method'] = gaia.get('method', 'All')

        if gaia.get('domain'):
            gaia['host'] = gaia['host'] + '.' + gaia.get('domain')

        # print gaia['host']

    if datastore:
        datastore = cleanParams(datastore)

    session['host'] = gaia['host']

    login(username=gaia['username'], password=gaia['password'])

    response = {
        'error': True,
        'message': 'Failed to log'
    }

    if session['alive'] == True:
        data = getData(gaia['method'])
        data['host'] = gaia['host']

        ds_type = datastore.get('type', 'elastic')

        if (ds_type == 'elastic'):
            es = setElasticSearch(
                datastore.get('host',''), 
                datastore.get('port' ,''),
                datastore.get('username',''),
                datastore.get('password',''),
                datastore.get('ca_path',''))

            data['@timestamp'] = datetime.datetime.utcnow()

            response = index2Elastic(
                es=es, 
                index=datastore.get('index','Default-'), 
                data=data, 
                method=gaia['method'])

        if (ds_type == 'logstash'):
            ls = setLogstash(
                datastore.get('host',''), 
                datastore.get('port' ,''),
                datastore.get('username',''),
                datastore.get('password',''),
                datastore.get('version',1),
                datastore.get('ssl',False)
            )

            response = index2logstash(
                ls=ls,
                data=data, 
                method=gaia['method'])

    else:

        response = session['message']

    module.exit_json(changed=False, ansible_module_results=response)


# Get the show on the road
if __name__ == '__main__':
    main()
