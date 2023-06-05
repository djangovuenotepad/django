import json
import requests,pprint
import time
from typing import Dict
from huaweicloudsdkcore.auth.credentials import BasicCredentials
from huaweicloudsdkwaf.v1.region.waf_region import WafRegion
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkwaf.v1 import *
from huaweicloudsdkcdn.v1 import *
from huaweicloudsdkcdn.v1.region.cdn_region import CdnRegion
from huaweicloudsdkcore.auth.credentials import GlobalCredentials
from huaweicloudsdkcore.exceptions import exceptions as hwexceptions
from huaweicloudsdkiam.v3 import *
from huaweicloudsdkdns.v2.region.dns_region import DnsRegion
from huaweicloudsdkdns.v2 import *

import app.signer as signer

class Hwwaf():
    def __init__(self, ak, sk, domain):
        self.ak = ak
        self.sk = sk
        self.domain = domain
        self.client = WafClient.new_builder() \
            .with_credentials(BasicCredentials(self.ak, self.sk)) \
            .with_region(WafRegion.value_of("ap-southeast-1")) \
            .build()

    def select_waf_source(self):
        try:
            request = ListHostRequest()

            request.hostname = self.domain
            response = self.client.list_host(request)
            instance_id = response.to_dict()['items'][0]['id']
            request = ShowHostRequest()
            request.instance_id = instance_id
            response = self.client.show_host(request)
            return  {"msg": response.to_dict(), "code": 200}
        except exceptions.ClientRequestException as e:
            return {"msg": str(e.error_msg), "code": 5001}

class Hwkey():
    def __init__(self, ak, sk, domainId):
        self.ak = ak
        self.sk = sk
        # sdk无法自动获取当前用户的domainId，请手动输入domainId; 如果不想手动指定domainId，请使用主账号登录或者给当前账号授权为管理员账号
        endpoint = "https://iam.cn-north-1.myhuaweicloud.com"
        self.client = IamClient.new_builder() \
            .with_credentials(GlobalCredentials(self.ak, self.sk, domainId)) \
            .with_endpoint(endpoint) \
            .build()

    def select_AccessKey(self, iam_id):
        request = ListPermanentAccessKeysRequest()
        request.user_id = iam_id
        response = self.client.list_permanent_access_keys(request)
        print(response)
        return response

    def delete_AccessKey(self, ak):
        request = DeletePermanentAccessKeyRequest()
        request.access_key = ak
        response = self.client.delete_permanent_access_key(request)
        print(response)
        return response

    def create_AccessKey(self, iam_id):
        request = CreatePermanentAccessKeyRequest()
        credentialbody = CreateCredentialOption(user_id=iam_id)
        request.body = CreatePermanentAccessKeyRequestBody(credential=credentialbody)
        response = self.client.create_permanent_access_key(request)
        print(response)
        return response


def get_refresh_type(uri: str):
    if uri == '':
        return 'directory'
    if not uri.startswith('/'):
        raise Exception('uri 必须以斜杠开头')
    elif uri.endswith('/'):
        return 'directory'
    else:
        return 'file'


def HUAWEICDNConfig(domain, ak, sk):
    credentials = GlobalCredentials(ak, sk)
    client = CdnClient.new_builder().with_credentials(credentials).with_region(CdnRegion.value_of("cn-north-1")).build()
    try:
        request = ListDomainsRequest()
        request.domain_name = domain
        request.page_size = 10
        request.page_number = 1
        request.enterprise_project_id = "ALL"
        response = client.list_domains(request)
        return {"msg": response.to_dict()['domains'][0]['sources'], "code": 200}
    except hwexceptions.ClientRequestException as err:
        return {"msg": str(err), "code": 5001}


class HwcDnsApi:
    def __init__(self, key, secret, domain_name: str, url='https://dns.myhuaweicloud.com'):
        self.sig = signer.Signer()
        self.sig.Key = key
        self.sig.Secret = secret
        self.url = url
        self.domain_hostname = domain_name.split('.')[0]
        self.domain = domain_name.lstrip(self.domain_hostname).lstrip('.')
        self.domain_name = domain_name

        self.credentials = BasicCredentials(key, secret)
        self.client = DnsClient.new_builder() \
                .with_credentials(self.credentials) \
                .with_region(DnsRegion.value_of("cn-east-3")) \
                .build()

    def get_domain_dns_record(self, zone_type='public'):
        '''
        url = f"{self.url}/v2/recordsets?zone_type={zone_type}&name={self.domain_name}"
        r = signer.HttpRequest(method="GET", url=url)
        r.headers = {"Content-Type": "application/json"}
        # 进行签名
        self.sig.Sign(r)
        # 发送请求
        res = requests.request(r.method, r.scheme + "://" + r.host + r.uri, headers=r.headers, data=r.body)
        print(json.dumps(res.json(), indent=4))
        if res.status_code == 200:
            # 华为DNS查询域名解析是模糊匹配，这里过滤一下，精确返回我们要查询的域名解析记录
            if len(res.json()['recordsets']) > 1:
                domains = []
                for sub_record in res.json()['recordsets']:
                    ret_domain = sub_record['name']
                    if ret_domain == f'{self.domain_name}.':
                        domains.append(sub_record)
                return {'msg': domains, 'can_delete': True, 'can_add': True, 'code': 200}
            else:
                return {'msg': res.json()['recordsets'], 'can_delete': True, 'can_add': True, 'code': 200}

        else:
            return {'msg': res.json(), 'code': res.status_code}
        '''
        try:
            request = ListRecordSetsWithLineRequest()
            request.name = self.domain_name
            response = self.client.list_record_sets_with_line(request)
            msg = response.to_json_object()['recordsets']
            domains=[]
            for sub_record in msg:
                ret_domain = sub_record['name']
                if ret_domain == f'{self.domain_name}.':
                    domains.append(sub_record)
            return {'msg': domains, 'can_delete': True, 'can_add': True, 'code': 200}
        except exceptions.ClientRequestException as e:
            return {'msg': str(e.error_msg),'code': e.status_code}
    def update_domain_dns_record(self, item: Dict):
        zone_id = item.get('zone_id')
        recordset_id = item.get('id')
        name = item.get('name')
        type = item.get('type')
        ttl = int(item.get('ttl'))
        records = item.get('records').split('\n')
        # url = f"{self.url}/v2/zones/{zone_id}/recordsets/{recordset_id}"
        url = item.get('links').get('self')
        r = signer.HttpRequest(method="PUT", url=url)
        r.headers = {"Content-Type": "application/json"}
        data = {
            "name": name,
            "type": type,
            "ttl": ttl,
            "records": records
        }
        r.body = json.dumps(data)
        # 进行签名
        self.sig.Sign(r)
        # 发送请求
        res = requests.request(r.method, r.scheme + "://" + r.host + r.uri, headers=r.headers, data=r.body)
        if res.status_code == 202:
            return {'msg': '修改成功', 'code': 200}
        else:
            return {'msg': res.json(), 'code': res.status_code}

    def delete_domain_dns_record(self, item: Dict):
        url = item.get('links').get('self')
        r = signer.HttpRequest(method="DELETE", url=url)
        r.headers = {"Content-Type": "application/json"}

        # 进行签名
        self.sig.Sign(r)
        # 发送请求
        res = requests.request(r.method, r.scheme + "://" + r.host + r.uri, headers=r.headers, data=r.body)
        if res.status_code == 202:
            return {'msg': '删除成功', 'code': 200}
        else:
            return {'msg': res.json(), 'code': res.status_code}


class HwcCdnApi:
    def __init__(self, key, secret, domain_name):
        self.sig = signer.Signer()
        self.sig.Key = key
        self.sig.Secret = secret
        self.domain_name = domain_name
        self.domain_id_and_enterprise_project_id_dict = self.get_domain_id_and_enterprise_project_id(domain_name)
        self.domain_id = self.domain_id_and_enterprise_project_id_dict['domain_id']
        self.enterprise_project_id = self.domain_id_and_enterprise_project_id_dict['enterprise_project_id']

    def get_domain_id_and_enterprise_project_id(self, domain_name):
        url = f"https://cdn.myhuaweicloud.com/v1.0/cdn/domains?domain_name={domain_name}&enterprise_project_id=ALL"
        r = signer.HttpRequest(method="GET", url=url)
        r.headers = {"Content-Type": "application/json"}
        # 进行签名
        self.sig.Sign(r)
        # 发送请求
        res = requests.request(r.method, r.scheme + "://" + r.host + r.uri, headers=r.headers, data=r.body)
        print(res.status_code)
        print(res.json())
        res_json = res.json()
        return {'domain_id': res_json['domains'][0]['sources'][0]['domain_id'],
                'enterprise_project_id': res_json['domains'][0]['enterprise_project_id']}

    def create_refresh_tasks(self, uri):
        # 创建刷新缓存任务
        if not uri:
            refresh_url = f'https://{self.domain_name}/'
        else:
            refresh_url = f'https://{self.domain_name}{uri}'
        url = f"https://cdn.myhuaweicloud.com/v1.0/cdn/content/refresh-tasks?enterprise_project_id={self.enterprise_project_id}"
        r = signer.HttpRequest(method="POST", url=url)
        r.headers = {"Content-Type": "application/json"}
        data = {
            "refresh_task": {
                "type": get_refresh_type(uri),
                "urls": [refresh_url]
            }
        }

        r.body = json.dumps(data)
        # 进行签名
        self.sig.Sign(r)
        res = requests.request(r.method, r.scheme + "://" + r.host + r.uri, headers=r.headers, data=r.body)
        res_json = res.json()
        if res.status_code != 200:
            raise Exception(res_json.get('error').get('error_msg'))
        if res_json.get('error'):
            raise Exception(res_json.get('error').get('error_msg'))
        return res.json()  # {'refresh_task': '882538449'}

    def query_refresh_tasks(self, history_tasks_id):
        # 查询cdn刷新任务
        url = f"https://cdn.myhuaweicloud.com/v1.0/cdn/historytasks/{history_tasks_id}/detail?enterprise_project_id={self.enterprise_project_id}"

        r = signer.HttpRequest(method="GET", url=url)
        r.headers = {"Content-Type": "application/json"}
        # 进行签名
        self.sig.Sign(r)
        # 发送请求
        res = requests.request(r.method, r.scheme + "://" + r.host + r.uri, headers=r.headers, data=r.body)
        return res.json()

    def exec_my_hwc_refresh_task(self, uri):
        print('###开始创建cdn刷新任务...', flush=True)
        start = time.time()
        create_refresh_tasks_result = self.create_refresh_tasks(uri=uri)
        task_id = create_refresh_tasks_result['refresh_task']

        # 查询刷新是否完成
        print('###开始查询任务进度...', flush=True)
        while True:
            time.sleep(60)
            query_refresh_tasks_result = self.query_refresh_tasks(history_tasks_id=task_id)
            status = query_refresh_tasks_result['status']
            if status == 'task_inprocess':
                print('###任务正在在执行中，请耐心等待...', flush=True)
            elif status == 'task_done':
                print('###任务执行成功：', flush=True)
                break

        # 格式化输出执行结果
        for k, v in query_refresh_tasks_result.items():
            print(f'\t{k}: {v}')
        print(f'###本次任务耗时：{time.time() - start}(s)', flush=True)
        return "刷新完成"

    def get_domain_cdn_source_info(self):

        url = f"https://cdn.myhuaweicloud.com/v1.0/cdn/domains/{self.domain_id}/detail?enterprise_project_id={self.enterprise_project_id}"
        r = signer.HttpRequest(method="GET", url=url)
        r.headers = {"Content-Type": "application/json"}
        # 进行签名
        self.sig.Sign(r)
        # 发送请求
        res = requests.request(r.method, r.scheme + "://" + r.host + r.uri, headers=r.headers, data=r.body)
        print(res.status_code)
        print(res.json())
        res_json = res.json()
        return res_json['domain']['sources']


if __name__ == '__main__':
    pass