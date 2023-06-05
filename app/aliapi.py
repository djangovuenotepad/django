import json
import time
import traceback
from pprint import pprint
from typing import Dict
from aliyunsdkalidns.request.v20150109.DescribeDnsGtmInstanceAddressPoolsRequest import \
    DescribeDnsGtmInstanceAddressPoolsRequest
from aliyunsdkalidns.request.v20150109.DescribeDnsGtmInstanceAddressPoolRequest import \
    DescribeDnsGtmInstanceAddressPoolRequest
from aliyunsdkalidns.request.v20150109.AddDomainRecordRequest import AddDomainRecordRequest
from aliyunsdkalidns.request.v20150109.DeleteDomainRecordRequest import DeleteDomainRecordRequest
from aliyunsdkalidns.request.v20150109.DescribeDomainRecordsRequest import DescribeDomainRecordsRequest
from aliyunsdkalidns.request.v20150109.UpdateDomainRecordRequest import UpdateDomainRecordRequest
from aliyunsdkcdn.request.v20180510.DescribeRefreshTaskByIdRequest import DescribeRefreshTaskByIdRequest
from aliyunsdkcdn.request.v20180510.DescribeUserDomainsRequest import DescribeUserDomainsRequest
from aliyunsdkcdn.request.v20180510.RefreshObjectCachesRequest import RefreshObjectCachesRequest
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkcore.auth.credentials import AccessKeyCredential
from aliyunsdkcore.client import AcsClient
from aliyunsdkdcdn.request.v20180115.BatchDeleteDcdnDomainConfigsRequest import BatchDeleteDcdnDomainConfigsRequest
from aliyunsdkdcdn.request.v20180115.BatchSetDcdnDomainConfigsRequest import BatchSetDcdnDomainConfigsRequest
from aliyunsdkdcdn.request.v20180115.DescribeDcdnDomainConfigsRequest import DescribeDcdnDomainConfigsRequest
from aliyunsdkdcdn.request.v20180115.DescribeDcdnRefreshTasksRequest import DescribeDcdnRefreshTasksRequest
from aliyunsdkdcdn.request.v20180115.DescribeDcdnUserDomainsRequest import DescribeDcdnUserDomainsRequest
from aliyunsdkdcdn.request.v20180115.RefreshDcdnObjectCachesRequest import RefreshDcdnObjectCachesRequest
from aliyunsdkram.request.v20150501.CreateAccessKeyRequest import CreateAccessKeyRequest
from aliyunsdkram.request.v20150501.DeleteAccessKeyRequest import DeleteAccessKeyRequest
from aliyunsdkram.request.v20150501.ListAccessKeysRequest import ListAccessKeysRequest
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkcore.auth.credentials import AccessKeyCredential
from aliyunsdkcore.auth.credentials import StsTokenCredential
from aliyunsdkdcdn.request.v20180115.DescribeDcdnUserDomainsRequest import DescribeDcdnUserDomainsRequest

class Alikey():
    def __init__(self, ID, Secret):
        self.ID = ID
        self.Secret = Secret
        self.client = AcsClient(region_id='cn-shanghai', credential=AccessKeyCredential(self.ID, self.Secret))

    def select_AccessKey(self):
        request = ListAccessKeysRequest()
        request.set_accept_format('json')
        response = self.client.do_action_with_exception(request)
        return str(response, encoding='utf-8')

    def delete_AccessKey(self, ID):
        request = DeleteAccessKeyRequest()
        request.set_accept_format('json')
        request.set_UserAccessKeyId(ID)
        response = self.client.do_action_with_exception(request)
        return str(response, encoding='utf-8')

    def create_AccessKey(self):
        request = CreateAccessKeyRequest()
        request.set_accept_format('json')
        response = self.client.do_action_with_exception(request)
        return str(response, encoding='utf-8')


class AliyunDnsApi:
    # DNS
    def __init__(self, access_key_id, access_key_secret, region_id='cn-hangzhou'):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.region_id = region_id
        self.client = self.create_client()

    def create_client(self):
        credentials = AccessKeyCredential(self.access_key_id, self.access_key_secret)
        return AcsClient(region_id='cn-hangzhou', credential=credentials)

    def get_domain_dns_record(self, domain_name: str):
        # 获取域名解析记录
        D1 = f"{domain_name.rsplit('.')[-2]}.{domain_name.rsplit('.')[-1]}"
        D2 = domain_name.rsplit('.')[0]
        request = DescribeDomainRecordsRequest()
        request.set_DomainName(D1)
        mess = json.loads(self.client.do_action_with_exception(request).decode())
        msg = []
        for i in mess['DomainRecords']['Record']:
            if i['RR'] == D2:
                msg.append(i)
        if len(msg) > 1:
            can_delete = False
        else:
            can_delete = True
        if msg[0]['Type'] == 'A':
            can_add = False
        else:
            can_add = True

        return {'msg': msg, 'can_delete': can_delete, 'can_add': can_add, 'code': 200}

    def update_domain_dns_record(self, item: Dict):
        # 修改域名解析记录
        try:
            request = UpdateDomainRecordRequest()
            request.set_accept_format('json')
            request.set_RR(item.get('RR'))
            request.set_RecordId(item.get('RecordId'))
            request.set_Type(item.get('Type'))
            request.set_Value(item.get('Value'))
            request.set_Line(item.get('Line'))
            request.set_TTL(item.get('TTL'))
            response = self.client.do_action_with_exception(request)
            json_response = json.loads(response)
            print(json_response)
            if json_response:
                return {'msg': '修改成功', 'code': 200}
        except ServerException as e:
            if 'The DNS record already exists' in str(e):
                return {'msg': '已存在，无需修改', 'code': 5001}
            else:
                raise Exception(e)

    def add_domain_dns_record(self, item: Dict):
        # 新增A记录解析值
        try:
            request = AddDomainRecordRequest()
            request.set_accept_format('json')
            request.set_DomainName(item.get('DomainName'))
            request.set_RR(item.get('RR'))
            request.set_Type(item.get('Type'))
            request.set_Value(item.get('Value'))
            response = self.client.do_action_with_exception(request)
            json_response = json.loads(response)
            print(json_response)
            if json_response:
                return {'msg': '修改成功', 'code': 200}
        except Exception as e:
            return {'msg': f'修改失败 {e}', 'code': 5001}

    def delete_domain_dns_record(self, item: Dict):
        try:
            request = DeleteDomainRecordRequest()
            request.set_accept_format('json')
            request.set_RecordId(item.get("RecordId"))
            response = self.client.do_action_with_exception(request)
            json_response = json.loads(response)
            print(json_response)
            if json_response:
                return {'msg': '删除成功', 'code': 200}
        except Exception as e:
            return {'msg': f'删除失败 {e}', 'code': 5001}


class AliyunCdnApi:
    # CDN
    def __init__(self, access_key_id, access_key_secret, region_id='cn-hangzhou'):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.region_id = region_id
        self.client = self.create_client()

    def create_client(self):
        credentials = AccessKeyCredential(self.access_key_id, self.access_key_secret)
        return AcsClient(region_id='cn-hangzhou', credential=credentials)

    def create_cdn_refresh_request(self, refresh_url, refresh_type):
        request = RefreshObjectCachesRequest()
        request.set_accept_format('json')
        request.set_ObjectPath(refresh_url)
        request.set_ObjectType(refresh_type)
        response = self.client.do_action_with_exception(request)
        return json.loads(response)

    def get_cdn_refresh_result(self, task_id):
        request = DescribeRefreshTaskByIdRequest()
        request.set_accept_format('json')
        request.set_TaskId(task_id)
        response = self.client.do_action_with_exception(request)
        return json.loads(response)

    def exec_aliyun_cdn_refresh_task(self, refresh_url, refresh_type):
        refresh_data = self.create_cdn_refresh_request(refresh_url=refresh_url, refresh_type=refresh_type)
        if refresh_data:
            refresh_task_id = refresh_data.get('RefreshTaskId')
            while True:
                refresh_result = self.get_cdn_refresh_result(task_id=refresh_task_id)
                refresh_result_log = refresh_result.get('Tasks')
                if refresh_result_log:
                    task = refresh_result_log[0]
                    task_ref_url = task.get("ObjectPath")
                    if task.get('Status') == "Complete":
                        print(f'\t [{task_ref_url}] 当前进度: 已完成', flush=True)
                        break
                    else:
                        print(f'\t [{task_ref_url}] 当前进度: {task.get("Process")}', flush=True)
                time.sleep(3)
            return "刷新完成"

    def get_domain_cdn_source_info(self, domain_name):
        # 获取源站配置
        request = DescribeUserDomainsRequest()
        request.set_accept_format('json')
        request.set_DomainName(domain_name)
        response = self.client.do_action_with_exception(request)
        json_response = json.loads(response)
        return {"msg": json_response.get('Domains').get('PageData')[0].get('Sources').get('Source'), "code": 200}


class AliyunDcdnApi:
    # DCDN
    def __init__(self, access_key_id, access_key_secret, region_id='cn-hangzhou'):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.region_id = region_id
        self.client = self.create_client()

    def create_client(self):
        credentials = AccessKeyCredential(self.access_key_id, self.access_key_secret)
        return AcsClient(region_id='cn-hangzhou', credential=credentials)

    def create_dcdn_refresh_request(self, refresh_url, refresh_type):
        request = RefreshDcdnObjectCachesRequest()
        request.set_accept_format('json')
        request.set_ObjectPath(refresh_url)
        request.set_ObjectType(refresh_type)
        response = self.client.do_action_with_exception(request)
        return json.loads(response)

    def get_dcdn_refresh_result(self, task_id):
        request = DescribeDcdnRefreshTasksRequest()
        request.set_accept_format('json')
        request.set_TaskId(task_id)
        response = self.client.do_action_with_exception(request)
        return json.loads(response)

    def exec_aliyun_dcdn_refresh_task(self, refresh_url, refresh_type):
        refresh_data = self.create_dcdn_refresh_request(refresh_url=refresh_url, refresh_type=refresh_type)
        if refresh_data:
            refresh_task_id = refresh_data.get('RefreshTaskId')
            while True:
                refresh_result = self.get_dcdn_refresh_result(task_id=refresh_task_id)
                refresh_result_log = refresh_result.get('Tasks').get('Task')
                if refresh_result_log:
                    task = refresh_result_log[0]
                    task_ref_url = task.get("ObjectPath")
                    if task.get('Status') == "Complete":
                        print(f'\t [{task_ref_url}] 当前进度: 已完成', flush=True)
                        break
                    else:
                        print(f'\t [{task_ref_url}] 当前进度: {task.get("Process")}', flush=True)
                time.sleep(3)
            return "刷新完成"

    def get_domain_dcdn_source_info(self, domain_name):
        try:
            request = DescribeDcdnUserDomainsRequest()
            request.set_accept_format('json')
            request.set_DomainName(domain_name)
            response = self.client.do_action_with_exception(request)
            json_response = json.loads(response)
            if json_response.get('TotalCount') == 0:
                return {"msg": str(json_response), "code": 5001}
            else:
                return {"msg": json_response.get('Domains').get('PageData')[0].get('Sources').get('Source'),
                        "code": 200}
        except Exception as err:
            return {"msg": str(err), "code": 5001}

    def domain_in_dcdn(self, domain_name):   #获取用户的全站加速域名
        request = DescribeDcdnUserDomainsRequest()
        request.set_accept_format('json')
        request.set_DomainName(domain_name)
        response = self.client.do_action_with_exception(request)
        json_response = json.loads(response)
        if json_response['Domains']['PageData']:
            return True
        else:
            return  False
    def domain_all_in_dcdn(self, ):   #获取用户的全站加速域名
        request = DescribeDcdnUserDomainsRequest()
        request.set_accept_format('json')
        request.set_PageSize(500)
        response = self.client.do_action_with_exception(request)
        json_response = json.loads(response)
        all_domain = []
        for i in json_response['Domains']['PageData']:
            all_domain.append(i['DomainName'])
        return all_domain
class AliDCDNApi:
    def __init__(self, acc_key_id, acc_key_srt):
        self.acc_key_id = acc_key_id
        self.acc_key_srt = acc_key_srt
        self.acc_region = 'ap-southeast-1'
        self.client = self.get_client()

    def get_client(self):
        return AcsClient(self.acc_key_id, self.acc_key_srt, self.acc_region)

    def get_config_id(self, _domain: str, _fun_name: str):
        """
        获取DCDN中指定配置项的配置ID

        Args:
            _domain (str): 要查询的域名(仅支持单个域名查询)
            _fun_name (str): 配置项名称
                             参考 https://next.api.aliyun.com/document/dcdn/2018-01-15/DescribeDcdnDomainConfigs?spm=api-workbench.API%20Explorer.0.0.5a361e0fnoeD2Y
        """
        request = DescribeDcdnDomainConfigsRequest()
        request.set_accept_format('json')
        request.set_DomainName(_domain)
        request.set_FunctionNames(_fun_name)
        res_data = {'configid': "", 'msg': f"域名[{_fun_name}]配置ID获取成功", 'code': 200}
        try:
            response = self.client.do_action_with_exception(request)
            data = json.loads(response)
            if data:
                if data['DomainConfigs']['DomainConfig']:
                    config_id = data['DomainConfigs']['DomainConfig'][0]['ConfigId']
                    res_data['configid'] = config_id
            # pprint(json.dumps(res_data, sort_keys=True, indent=2))
        except Exception as e:
            res_data['code'] = 0
            res_data['msg'] = f"域名[{_fun_name}]配置ID获取失败,Info:{e} {traceback.format_exc()}"
        finally:
            return res_data

    def delete_domain_config(self, _domain_list: list, _fun_name_list: list):
        """
        删除域名指定配置项
        :param _domain_list: 要操作的域名列表
        :param _fun_name_list: 要删除的配置项列表
        """
        data = {'success': False}
        # cdn接收域名与ip列表是字符串形式的，并以','逗号分隔
        _domains_str = ','.join(_domain_list)
        _fun_name_str = ','.join(_fun_name_list)
        request = BatchDeleteDcdnDomainConfigsRequest()
        request.set_accept_format('json')
        request.set_DomainNames(_domains_str)
        request.set_FunctionNames(_fun_name_str)
        try:
            response = self.client.do_action_with_exception(request)
            data = json.loads(response)
            data['msg'] = "操作成功"
            data['success'] = True
        except Exception:
            data['msg'] = traceback.format_exc()
        finally:
            return data

    def get_domain_ip_allow_list(self, _domain: str):
        """
        获取域名IP白名单列表
        :param _domain: 要查询的域名
        """
        request = DescribeDcdnDomainConfigsRequest()
        request.set_accept_format('json')
        request.set_DomainName(_domain)
        request.set_FunctionNames("ip_allow_list_set")
        res_data = {'ip_list': "", 'msg': "域名IP白名单列表获取成功", 'code': 200}
        try:
            response = self.client.do_action_with_exception(request)
            data = json.loads(response)
            if data:
                print('\t', data, flush=True)
                if data['DomainConfigs']['DomainConfig']:
                    ip_list = data['DomainConfigs']['DomainConfig'][0]['FunctionArgs']['FunctionArg'][0]['ArgValue']
                    res_data['ip_list'] = ip_list
                else:
                    res_data['code'] = 404
                    res_data['msg'] = '域名IP白名单列表为空'
            # pprint(json.dumps(res_data, sort_keys=True, indent=2))
        except Exception as e:
            res_data['code'] = 0
            res_data['msg'] = f'域名IP白名单列表获取失败,Info:{e}'
        finally:
            return res_data

    def set_domain_ip_allow_list(self, _domain_list: list, _ip_list: list):
        """
        设置域名IP白名单列表
        :param _domain_list: 要配置的域名列表
        :param _ip_list: 要配置的IP列表
        """
        data = {'success': False}
        # cdn接收域名与ip列表是字符串形式的，并以','逗号分隔
        _domains_str = ','.join(_domain_list)
        _iplist_str = ','.join(_ip_list)
        request = BatchSetDcdnDomainConfigsRequest()
        request.set_accept_format('json')
        request.set_DomainNames(_domains_str)
        request.set_Functions(
            [
                {
                    "functionArgs": [
                        {"argName": "ip_list", "argValue": _iplist_str}
                    ],
                    "functionName": "ip_allow_list_set"
                }
            ]
        )
        try:
            response = self.client.do_action_with_exception(request)
            data = json.loads(response)
            data['msg'] = "操作成功"
            data['success'] = True
        except Exception as e:
            data['msg'] = traceback.format_exc()
        finally:
            return data

    def get_dcdn_domains(self, _resource_group_id: str = None, _domain_status: str = None, _domain_name: str = None):
        """
        接口文档：https://next.api.aliyun.com/api/dcdn/2018-01-15/DescribeDcdnUserDomains
        获取DCDN上所有域名，支持域名模糊匹配过滤和域名状态过滤
        :param _resource_group_id: 资源组ID
        :param _domain_name: 域名模糊匹配字符
        :param _domain_status: 域名状态过滤
        域名状态说明：
            online：启用。
            offline：停用。
            configuring：配置中。
            configure_failed：配置失败。
            checking：正在审核。
            check_failed：审核失败。
        """
        request = DescribeDcdnUserDomainsRequest()
        request.set_accept_format('json')
        request.set_PageSize(100)
        if _resource_group_id:
            request.set_ResourceGroupId(_resource_group_id)
        if _domain_status:
            request.set_domainStatus(_domain_status)
        if _domain_name:
            request.set_DomainName(_domain_name)
        try:
            response = self.client.do_action_with_exception(request)
            return json.loads(response)
        except Exception as e:
            pprint(e)


class AliGTMapi:
    def __init__(self, access_key_id, access_key_secret, region_id='cn-hangzhou'):
        self.access_key_id = access_key_id
        self.access_key_secret = access_key_secret
        self.region_id = region_id
        self.client = self.create_client()

    def create_client(self):
        credentials = AccessKeyCredential(self.access_key_id, self.access_key_secret)
        return AcsClient(region_id='cn-hangzhou', credential=credentials)

    def source_info(self, AddrPollId: str):
        request = DescribeDnsGtmInstanceAddressPoolsRequest()
        request.set_accept_format('json')
        request.set_InstanceId(AddrPollId)
        response = self.client.do_action_with_exception(request)
        AddrPoll = str(response, encoding='utf-8')
        # 获取地址池列表
        AddrPollIds = [i['AddrPoolId'] for i in json.loads(AddrPoll)['AddrPools']['AddrPool']]
        data = []
        for AddrPollId in AddrPollIds:
            request = DescribeDnsGtmInstanceAddressPoolRequest()
            request.set_accept_format('json')
            request.set_AddrPoolId(AddrPollId)
            response = self.client.do_action_with_exception(request)
            data.append(json.loads(str(response, encoding='utf-8')))
        _data = {}
        for i in data:
            _ip = []
            for count in i['Addrs']['Addr']:
                _ip.append(count['Addr'])

            _data[i['Name']] = _ip

        return _data


if __name__ == '__main__':
    # result = aliyun_dns_client.update_domain_dns_record(item)
    # aliyun_dcdn_client = AliyunDcdnApi("LTAI5tFhuVq4iCZitRx2Xk6f", "v6nxg3XoyINhOHmslDmfUewcvWPWQL")
    # result = aliyun_dcdn_client.get_domain_dcdn_source_info('bybackadmin.blkvha.com')
    # result = aliyun_dcdn_client.exec_aliyun_dcdn_refresh_task(refresh_url,refresh_type)
    # print(result)
    # ali = Alikey('LTAI5tKZifTHNakgVW9gQwVW', 'JobT8oBIGGtgkWZYt6IBEn1SGdLdRU')
    # print(ali.select_AccessKey())  # 查询账户下的所有 AccessKey
    # print(ali.delete_AccessKey('LTAI5tKBxyZXxeZtsPKMj6LG'))  # 删除账户下的指定 AccessKey
    # print(ali.create_AccessKey())  # 创建           AccessKey
    #api = AliGTMapi('LTAI5tP1wGZHAxawBVE8AkHz', 'Fqr2hUmMLUXKaTWJPGM5XRobMeWncB')
    #msg = api.source_info('gtm-cn-6ja22zcwd0r')
    #pprint(msg, indent=2)
    ali = AliyunDcdnApi('LTAI5tHBLpx6tw3uPYSCf4th','3T4YaHFwlqbAMsGwoBR96IWYgnFgrV').domain_all_in_dcdn()
    print(ali)
