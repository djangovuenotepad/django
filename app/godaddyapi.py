import requests
from typing import Dict
import json


class GodaddyDnsApi:
    def __init__(self, godaddy_api_secret_key, domain_name: str):
        self.url = "https://api.godaddy.com"
        self.headers = {'Authorization': godaddy_api_secret_key, "Content-Type": "application/json"}
        self.doamin_host = domain_name.split('.')[0]
        self.domain = domain_name.lstrip(self.doamin_host).lstrip('.')

    def get_domain_dns_record(self):
        url = f"{self.url}/v1/domains/{self.domain}/records"
        res = requests.get(url=url, headers=self.headers)
        res_json = res.json()
        records_list = []
        for record in res_json:
            if record.get('name') == self.doamin_host:
                records_list.append(record)
        return {'msg': records_list, 'can_delete': True, 'can_add': True, 'code': 200}

    def update_domain_dns_record(self, item: Dict):
        url = f"{self.url}/v1/domains/{self.domain}/records/{item.get('type')}/{item.get('name')}"
        data = [
          {
            "data": item.get('data'),
            # "port": 80,
            # "priority": 0,
            # "protocol": "string",
            # "service": "string",
            "ttl": int(item.get('ttl')),
            # "weight": 0
          }
        ]
        res = requests.put(url=url, headers=self.headers, data=json.dumps(data))
        if res.status_code == 200:
            return {'msg': '修改成功', 'code': 200}
        else:
            raise Exception(res.json().get('message'))

    def delete_domain_dns_record(self, item: Dict):
        url = f"{self.url}/v1/domains/{self.domain}/records/{item.get('type')}/{item.get('name')}"
        res = requests.delete(url=url, headers=self.headers)
        if res.status_code == 204:
            return {'msg': '删除成功', 'code': 200}
        else:
            raise Exception(res.json().get('message'))
