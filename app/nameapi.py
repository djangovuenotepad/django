import requests
from typing import Dict
import json


class NameComDnsApi:
    def __init__(self, username, token, domain_name: str):
        self.url = "https://api.name.com"
        self.auth = (username, token)
        self.domain = domain_name.split('.')[-2] + '.' + domain_name.split('.')[-1]
        self.domain_host = domain_name.replace('.' + self.domain, '')

    def get_domain_dns_record(self):
        url = f"{self.url}/v4/domains/{self.domain}/records"
        res = requests.get(url=url, auth=self.auth)
        status_code = res.status_code
        res_json = res.json()
        # print(status_code,res_json)
        if status_code != 200:
            return {'msg': res_json.get('message') + ((',' + res_json.get('details')) if res_json.get('details') else ''), 'code': status_code}

        records_list = []
        for record in res_json.get('records'):
            if record.get('host') == self.domain_host:
                records_list.append(record)
        if len(records_list) > 1 :
                can_delete = False
        else:
                can_delete = True
        if records_list[0]['type'] == 'A':
            can_add = False
        else:
            can_add = True
        return {'msg': records_list, 'can_delete': can_delete, 'can_add': can_add, 'code': 200}

    def update_domain_dns_record(self, item: Dict):
        _id = item.get('id')
        _domain = item.get('domainName')
        _host = item.get('host')
        _fqdn = item.get('fqdn')
        _type = item.get('type')
        _answer = item.get('answer')
        _ttl = int(item.get('ttl'))
        _url = f"{self.url}/v4/domains/{self.domain}/records/{_id}"
        data = {
            'id': _id,
            'domainName': _domain,
            'host': _host,
            'fqdn': _fqdn,
            'type': _type,
            'answer': _answer,
            'ttl': _ttl
        }
        res = requests.put(url=_url, auth=self.auth, data=json.dumps(data))
        if res.status_code == 200:
            return {'msg': '修改成功', 'code': 200}
        else:
            raise Exception(res.json().get('message'))

    def add_domain_dns_record(self, item: Dict):
        _id = item.get('id')
        _domain = item.get('domainName')
        _host = item.get('host')
        _fqdn = item.get('fqdn')
        _type = item.get('type')
        _answer = item.get('answer')
        _ttl = int(item.get('ttl'))
        data = {

            'id': _id,
            'domainName': _domain,
            'host': _host,
            'fqdn': _fqdn,
            'type': _type,
            'answer': _answer,
            'ttl': _ttl
        }
        url = f"{self.url}/v4/domains/{self.domain}/records/"
        res = requests.post(url=url, auth=self.auth,data=json.dumps(data))
        if res.status_code == 200:
            return {'msg': '添加成功', 'code': 200}
        else:
            raise Exception(res.json().get('message'))

    def delete_domain_dns_record(self, item: Dict):
        _id = item.get('id')
        url = f"{self.url}/v4/domains/{self.domain}/records/{_id}"
        res = requests.delete(url=url, auth=self.auth)
        if res.status_code == 200:
            return {'msg': '删除成功', 'code': 200}
        else:
            raise Exception(res.json().get('message'))
