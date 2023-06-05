# coding: utf-8
# pip install huaweicloudsdkcdn
import time

from huaweicloudsdkcore.auth.credentials import GlobalCredentials
from huaweicloudsdkcdn.v1.region.cdn_region import CdnRegion
from huaweicloudsdkcore.exceptions import exceptions
from huaweicloudsdkcdn.v1 import *


class HUAWEI:
    def __init__(self, ak, sk):
        self.ak = ak
        self.sk = sk

    def ListDomains(self):
        credentials = GlobalCredentials(self.ak, self.sk)
        client = CdnClient.new_builder() \
            .with_credentials(credentials) \
            .with_region(CdnRegion.value_of("ap-southeast-1")) \
            .build()
        try:
            request = ListDomainsRequest()
            request.enterprise_project_id = "all"
            response = client.list_domains(request)
            print(response)
            return response
        except exceptions.ClientRequestException as e:
            print(e.status_code)
            print(e.request_id)
            print(e.error_code)
            print(e.error_msg)

    def UpdateDomainOrigin(self, domain_id, DomainOrigin):
        credentials = GlobalCredentials(self.ak, self.sk)
        client = CdnClient.new_builder() \
            .with_credentials(credentials) \
            .with_region(CdnRegion.value_of("ap-southeast-1")) \
            .build()
        try:
            request = UpdateDomainOriginRequest()
            request.domain_id = domain_id
            request.enterprise_project_id = "all"
            listSourcesOrigin = DomainOrigin
            originbody = ResourceBody(
                sources=listSourcesOrigin
            )
            request.body = OriginRequest(
                origin=originbody
            )
            response = client.update_domain_origin(request)
            print(response)
        except exceptions.ClientRequestException as e:
            print(e.status_code)
            print(e.request_id)
            print(e.error_code)
            print(e.error_msg)

    def Refresh(self,domains):
        credentials = GlobalCredentials(self.ak, self.sk)
        client = CdnClient.new_builder() \
            .with_credentials(credentials) \
            .with_region(CdnRegion.value_of("ap-southeast-1")) \
            .build()
        try:
            request = CreateRefreshTasksRequest()
            listUrlsRefreshTask = domains
            refreshTaskbody = RefreshTaskRequestBody(
                type="directory",
                urls=listUrlsRefreshTask
            )
            request.body = RefreshTaskRequest(
                refresh_task=refreshTaskbody
            )
            response = client.create_refresh_tasks(request)
            print(response)
        except exceptions.ClientRequestException as e:
            print(e.status_code)
            print(e.request_id)
            print(e.error_code)
            print(e.error_msg)

if __name__ == "__main__":

    opsweb_domains = [ 'devops.com']
    ak = "******"
    sk = "******"

    # 回源IP(模板)
    Origin = [("8.8.8.8", 1)]

    # 执行替换
    huawei = HUAWEI(ak, sk)
    cloud_domains = huawei.ListDomains().to_dict()['domains']
    DomainOrigin = []
    for i in Origin:
        DomainOrigin.append(
            SourceWithPort(
                ip_or_domain=i[0],
                origin_type="ipaddr",
                active_standby=i[1]
            ),
        )
    for i in cloud_domains:
        time.sleep(2)
        if i['domain_name'] in opsweb_domains:
            print(f"\n更新域名 {i['domain_name']} :")
            huawei.UpdateDomainOrigin(i['id'], DomainOrigin)
    #提交刷新缓存任务
    refresh_domains = []
    for i in  opsweb_domains:
        refresh_domains.append(f'https://{i}/')
    huawei.Refresh(domains=refresh_domains)