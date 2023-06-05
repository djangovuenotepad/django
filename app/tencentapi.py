import json
import time
import warnings
from typing import Dict

from tencentcloud.cdn.v20180606 import cdn_client, models
from tencentcloud.common import credential
from tencentcloud.common.exception.tencent_cloud_sdk_exception import TencentCloudSDKException
from tencentcloud.common.profile.client_profile import ClientProfile
from tencentcloud.common.profile.http_profile import HttpProfile
from tencentcloud.dnspod.v20210323 import dnspod_client, models
from tencentcloud.dnspod.v20210323 import models as dnsModels
from tencentcloud.ecdn.v20191012 import ecdn_client, models as ecdnModels
from tencentcloud.ecdn.v20191012 import models


def TENCENTECDNConfig(domain, ak, sk):
    try:
        cred = credential.Credential(ak, sk)
        httpProfile = HttpProfile()
        httpProfile.endpoint = "ecdn.tencentcloudapi.com"

        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        client = ecdn_client.EcdnClient(cred, "", clientProfile)

        req = models.DescribeDomainsConfigRequest()
        params = {
            "Filters": [{
                "Name": "domain",
                "Value": [domain]
            }]
        }
        req.from_json_string(json.dumps(params))

        resp = client.DescribeDomainsConfig(req)
        resp = resp.to_json_string()
        resp = json.loads(resp)
        return {"msg": resp['Domains'][0], "code": 200}
    except TencentCloudSDKException as err:
        return {"msg": str(err), "code": 5001}


def TENCENTCDNConfig(domain, ak, sk):
    try:
        cred = credential.Credential(ak, sk)
        httpProfile = HttpProfile()
        httpProfile.endpoint = "cdn.tencentcloudapi.com"

        clientProfile = ClientProfile()
        clientProfile.httpProfile = httpProfile
        client = cdn_client.CdnClient(cred, "", clientProfile)

        req = models.DescribeDomainsRequest()
        params = {
            "Filters": [
                {
                    "Name": "domain",
                    "Value": [domain]
                }
            ]
        }
        req.from_json_string(json.dumps(params))

        resp = client.DescribeDomains(req)
        resp = resp.to_json_string()
        resp = json.loads(resp)
        return {"msg": resp['Domains'][0], "code": 200}
    except TencentCloudSDKException as err:
        return {"msg": str(err), "code": 5001}


class TencentCloudCdnApi:
    def __init__(self, _secret_id, _secret_key):
        warnings.filterwarnings('ignore')
        self.secretId = _secret_id
        self.secretKey = _secret_key
        self.client = self.create_client()

    def create_client(self):
        cred = credential.Credential(self.secretId, self.secretKey)
        return cdn_client.CdnClient(cred, '')

    def create_cdn_refresh_request(self, refresh_url, refresh_type):
        # 刷新类型，flush：刷新产生更新的资源，delete：刷新全部资源。仅目录刷新时需要此参数
        FlushType = 'delete'
        res = None
        # 刷新目录
        if refresh_type == 'directory':
            req = models.PurgePathCacheRequest()
            params = {
                "Paths": [refresh_url],
                "FlushType": FlushType
            }
            req.from_json_string(json.dumps(params))
            res = self.client.PurgePathCache(req)
        # 刷新文件
        elif refresh_type == 'file':
            req = models.PurgeUrlsCacheRequest()
            params = {
                "Urls": [refresh_url]
            }
            req.from_json_string(json.dumps(params))
            res = self.client.PurgeUrlsCache(req)
        # 返回结果转为json dict
        res_json_str = res.to_json_string()
        return json.loads(res_json_str)

    def get_cdn_refresh_result(self, task_id: str):
        req = models.PurgeTask()
        params = {"TaskId": task_id}
        req.from_json_string(json.dumps(params))
        res = self.client.DescribePurgeTasks(req)
        res_json_str = res.to_json_string()
        return json.loads(res_json_str)

    def exec_tencentcloud_cdn_refresh_task(self, refresh_url, refresh_type):
        refresh_data = self.create_cdn_refresh_request(refresh_url=refresh_url, refresh_type=refresh_type)
        if refresh_data:
            refresh_task_id = refresh_data.get('TaskId')
            while True:
                refresh_result = self.get_cdn_refresh_result(task_id=refresh_task_id)
                refresh_result_log = refresh_result.get('PurgeLogs')
                if refresh_result_log:
                    task = refresh_result_log[0]
                    task_ref_url = task.get("Url")
                    if task.get('Status') == "done":
                        print(f'\t [{task_ref_url}] 当前进度: 已完成', flush=True)
                        break
                    else:
                        print(f'\t [{task_ref_url}] 当前进度: 节点刷新中...', flush=True)
                time.sleep(10)
            return "刷新完成"

    def get_domain_cdn_source_info(self, _domain_name):
        # 获取源站配置
        req = models.DescribeDomainsConfigRequest()
        params = {
            "Filters": [{"Name": "domain", "Value": [_domain_name]}]
        }
        req.from_json_string(json.dumps(params))
        res = self.client.DescribeDomainsConfig(req)
        res_json_str = res.to_json_string()
        res_json = json.loads(res_json_str)
        return res_json.get('Domains')[0].get('Origin')


class TencentCloudEcdnApi:
    def __init__(self, _secret_id, _secret_key):
        warnings.filterwarnings('ignore')
        self.secretId = _secret_id
        self.secretKey = _secret_key
        self.client = self.create_client()

    def create_client(self):
        cred = credential.Credential(self.secretId, self.secretKey)
        return ecdn_client.EcdnClient(cred, '')

    def get_domain_ecdn_source_info(self, _domain_name):
        # 获取源站配置
        req = ecdnModels.DescribeDomainsConfigRequest()
        params = {
            "Filters": [{"Name": "domain", "Value": [_domain_name]}]
        }
        req.from_json_string(json.dumps(params))
        res = self.client.DescribeDomainsConfig(req)
        res_json_str = res.to_json_string()
        res_json = json.loads(res_json_str)
        return res_json.get('Domains')[0].get('Origin')


class TencentCloudDnsApi:
    # dns解析
    def __init__(self, _secret_id, _secret_key):
        warnings.filterwarnings('ignore')
        self.secretId = _secret_id
        self.secretKey = _secret_key
        self.client = self.create_client()

    def create_client(self):
        cred = credential.Credential(self.secretId, self.secretKey)
        return dnspod_client.DnspodClient(cred, '')

    def get_domain_dns_record(self, _domain_name: str):
        # 获取域名解析记录
        try:
            Subdomain = _domain_name.split('.')[0]
            Domain = _domain_name.lstrip(Subdomain).lstrip('.')
            req = dnsModels.DescribeRecordListRequest()
            params = {
                "Domain": Domain,
                "Subdomain": Subdomain
            }
            req.from_json_string(json.dumps(params))
            res = self.client.DescribeRecordList(req)
            res_json_str = res.to_json_string()
            res_json = json.loads(res_json_str)
            if len(res_json['RecordList']) > 1:
                can_delete = False
            else:
                can_delete = True
            if res_json['RecordList'][0]['Type'] == 'A':
                can_add = False
            else:
                can_add = True
            return {'msg': res_json['RecordList'], 'can_delete': can_delete, 'can_add': can_add, 'code': 200}
        except TencentCloudSDKException as e:
            return {'msg': e.message, 'code': e.code}

    def add_domain_dns_record(self, item: Dict):
        SubDomain = item.get('Name')
        Domain = item.get('current_doamin_name').lstrip(SubDomain).lstrip('.')
        Domain = Domain.split(':')[0]
        # 实例化一个请求对象,每个接口都会对应一个request对象
        req = models.CreateRecordRequest()
        params = {
            "Domain": Domain,
            "SubDomain": SubDomain,
            "RecordType": item.get('Type'),
            "RecordLine": item.get('Line'),
            "Value": item.get('Value'),
        }
        req.from_json_string(json.dumps(params))

        # 返回的resp是一个DeleteRecordResponse的实例，与请求对象对应
        resp = self.client.CreateRecord(req)
        # 输出json格式的字符串回包
        print(resp.to_json_string())
        return '添加成功'

    def delete_domain_dns_record(self, item: Dict):
        SubDomain = item.get('Name')
        Domain = item.get('current_doamin_name').lstrip(SubDomain).lstrip('.')
        Domain = Domain.split(':')[0]
        # 实例化一个请求对象,每个接口都会对应一个request对象
        req = models.DeleteRecordRequest()
        params = {
            "Domain": Domain,
            "RecordId": int(item.get('RecordId'))
        }
        req.from_json_string(json.dumps(params))

        # 返回的resp是一个DeleteRecordResponse的实例，与请求对象对应
        resp = self.client.DeleteRecord(req)
        # 输出json格式的字符串回包
        print(resp.to_json_string())
        return '删除成功'

    def update_domain_dns_record(self, item: Dict):
        SubDomain = item.get('Name')
        Domain = item.get('current_doamin_name').lstrip(SubDomain).lstrip('.')
        Domain = Domain.split(':')[0]
        req = dnsModels.ModifyRecordRequest()
        params = {
            "Domain": Domain,
            "SubDomain": SubDomain,
            "RecordType": item.get('Type'),
            "RecordLine": item.get('Line'),
            "Value": item.get('Value'),
            "RecordId": int(item.get('RecordId')),
            "TTL": int(item.get('TTL')),
            "Status": item.get('Status')
        }
        req.from_json_string(json.dumps(params))
        res = self.client.ModifyRecord(req)
        res_json_str = res.to_json_string()
        res_json = json.loads(res_json_str)
        if res_json:
            return {'msg': '修改成功', 'code': 200}


if __name__ == '__main__':
    pass