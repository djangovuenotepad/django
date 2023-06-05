import boto3, time, json, pprint
import traceback


# pip3 install boto3
class AWSWAFApi:
    def __init__(self, _key_id: str, _key_secret: str):
        self.key_id = _key_id
        self.key_secret = _key_secret
        self.session = boto3.Session(
            aws_access_key_id=self.key_id,
            aws_secret_access_key=self.key_secret,
            region_name='us-east-1'
        )
        self.client = self.session.client('wafv2')

    def list_ip_sets(self):
        resp = self.client.list_ip_sets(
            Scope='CLOUDFRONT',
            Limit=100
        )
        return resp

    def get_ip_set(self, Name, Id):
        resp = self.client.get_ip_set(
            Name=Name,
            Scope='CLOUDFRONT',
            Id=Id
        )
        return resp

    def update_ip_set(self, Name, Id, Addresses, LockToken,Description ) -> str:
        """Name, Id, Description, Addresses, LockToken"""
        resp = self.client.update_ip_set(
            Name=Name,
            Scope='CLOUDFRONT',
            Id=Id,
            Description=Description,
            Addresses=Addresses,
            LockToken=LockToken
        )
        return resp

class AWSCDNApi:
    """AWS CloudFront API接口"""

    def __init__(self, _key_id: str, _key_secret: str):
        self.key_id = _key_id
        self.key_secret = _key_secret
        self.session = boto3.Session(
            aws_access_key_id=self.key_id,
            aws_secret_access_key=self.key_secret,
            region_name='global'
        )
        self.aws_cdn_api = self.session.client('cloudfront')
        self._distribution_config = None

    def get_distribution_config(self, _domain: str):
        """获取指定域名的分配配置信息
        :param _domain: 要查询的域名
        """
        try:
            resp = self.aws_cdn_api.list_distributions()
            distribution_list = resp['DistributionList']['Items']
            for _domain_distribution in distribution_list:
                if _domain in _domain_distribution['Aliases']['Items']:
                    self._distribution_config = _domain_distribution
        except Exception as e:
            print(e)

    def get_distribution_id(self, _domain: str):
        """获取对应分配ID
        :param _domain: 分配对应的CNMAE,AWS的CNMAE是指绑定的业务域名
        :return _distribution_id 分配对应的ID
        """
        self.get_distribution_config(_domain)
        if self._distribution_config:
            return self._distribution_config['Id']

    def invalidate_files(self, _distribution_id: str, _domain: str, _files_path: list):
        """
        使文件从缓存中失效
        :param _distribution_id: 分配ID
        :param _domain: 所属分配的CNAME AWS的CNMAE是指绑定的业务域名
        :param _files_path: 文件路径(可以指定单独文件的路径或以 * 通配符结尾的路径)，list 类型，
            可同时失效多个文件，计费还是以路径数计费，不影响。
            需要注意每个路径都要以"/"开头，即 "/" + key 全站刷新为: /*  指定目录刷新: /img/*
        """
        # 将所有路径后加上通配* 以兼容目录或全站刷新
        _files_path = [f'{i}*' for i in _files_path]

        # 文件路径数量，int 类型
        _quantity = len(_files_path)
        unique_tag = time.strftime('%Y%m%d%H%M%S', time.localtime())
        try:
            response = self.aws_cdn_api.create_invalidation(
                DistributionId=_distribution_id,
                InvalidationBatch={
                    'Paths': {
                        'Quantity': _quantity,
                        'Items': _files_path
                    },
                    'CallerReference': unique_tag
                }
            )
            return response['Invalidation']['Id']
        except self.aws_cdn_api.exceptions.ClientError as e:
            print(e.response)
            exit(1)

    def get_invalidation_status(self, _destribution_id: str, _invalidation_id: str):
        """
        获取缓存失效任务状态
        :param _destribution_id: 分配ID
        :param _invalidation_id: 缓存失效任务ID
        :return _invalidation_status
        """
        try:
            response = self.aws_cdn_api.get_invalidation(
                DistributionId=_destribution_id,
                Id=_invalidation_id
            )
            return response['Invalidation']['Status']
        except Exception as e:
            print(e)

    def get_cdn_domain_source_info(self, _domain: str):
        """获取域名所在分配的配站信息
        :param _domain: 分配对应的CNMAE,AWS的CNMAE是指绑定的业务域名
        """
        self.get_distribution_config(_domain)
        domain_source_info = {}
        origin_group_list = set()
        if self._distribution_config:

            # 默认行为源站
            default_cache_behaviors = self._distribution_config['DefaultCacheBehavior']
            default_cache_behaviors_origin = default_cache_behaviors['TargetOriginId']
            origin_group_list.add(default_cache_behaviors_origin)
            domain_source_info['DefaultCacheBehavior'] = {'originId': default_cache_behaviors_origin}

            # 自定义行为源站
            if self._distribution_config['CacheBehaviors']['Quantity'] >= 1:
                cache_behaviors = self._distribution_config['CacheBehaviors']
                domain_source_info['CacheBehaviors'] = []
                for i in cache_behaviors['Items']:
                    origin_group_list.add(i['TargetOriginId'])
                    domain_source_info['CacheBehaviors'].append(
                        {
                            'PathPattern': i['PathPattern'],
                            'originId': default_cache_behaviors_origin
                        }
                    )

            # 源
            if self._distribution_config['Origins']['Quantity'] >= 1:
                _origins = []
                for i in self._distribution_config['Origins']['Items']:
                    _origins.append(i['Id'])
                domain_source_info['Origins'] = _origins

            # 源组
            if self._distribution_config['OriginGroups']['Quantity'] >= 1:
                _origins = []
                for i in self._distribution_config['OriginGroups']['Items']:
                    _origins.append(i['Members'])
                domain_source_info['OriginsGroups'] = _origins

            return domain_source_info

    def exce_cdn_cache_refresh_task(self, _domain: str, _paths: str):
        """
        执行缓存刷新任务，并查询缓存结果
        :param _domain: 要刷新的域名
        :param _paths: 要刷新的路径，支持多个以‘,'逗号分隔
        """
        _path_list = _paths.split(',')
        distribution_id = self.get_distribution_id(_domain)

        print(f'>>> 开始刷新 AWS-CloudFront 缓存 ...\n\t分配: {distribution_id} '
              f'\n\t域名: {_domain} \n\t路径: {_path_list}')
        task_id = self.invalidate_files(_distribution_id=distribution_id, _domain=_domain, _files_path=_path_list)
        if task_id:
            print(f'\n>>> 查询任务[{task_id}]刷新进度: ...')
            while True:
                query_ret = self.get_invalidation_status(distribution_id, task_id)
                if query_ret == "Completed":
                    print('\n### 刷新完成!\n')
                    break
                else:
                    print('\t+++ 正在刷新中,请稍等 +++')
                    time.sleep(10)
            return "刷新完成"


class AWSIAMApi:
    """AWS IAM API接口"""

    def __init__(self, _key_id: str, _key_secret: str):
        self.key_id = _key_id
        self.key_secret = _key_secret
        self.session = boto3.Session(
            aws_access_key_id=self.key_id,
            aws_secret_access_key=self.key_secret,
            region_name='global'
        )
        self.aws_iam_api = self.session.client('iam')

    def get_users_basic_info(self):
        """
        列出所有用户基础信息
        """
        try:
            resp = self.aws_iam_api.list_users()
            return resp['Users']
        except Exception as e:
            print(f'{e}: {traceback.format_exc()}')

    def get_user_list(self):
        """
        获取所有用户列表
        """
        _users_info = self.get_users_basic_info()
        _user_list = [u['UserName'] for u in _users_info]
        return _user_list

    def list_user_access_key(self, _user: str = None):
        """
        列出所有accesskey的用户信息
        :param _user: 用户名 未指定则删除当前API accesskey所属用户的
        """

        if _user:
            resp = self.aws_iam_api.list_access_keys(UserName=_user)
        else:
            resp = self.aws_iam_api.list_access_keys()
        return resp['AccessKeyMetadata']

    def create_user_access_key(self, _user: str = None):
        """
        创建指定帐号access key
        :param _user: 用户名 未指定则删除当前API accesskey所属用户的
        """

        if _user:
            resp = self.aws_iam_api.create_access_key(UserName=_user)
        else:
            resp = self.aws_iam_api.create_access_key()
        return resp['AccessKey']

    def delete_user_access_key(self, _access_key_id: str, _user: str = None):
        """
        删除指定帐号access key
        :param _access_key_id: 要删除的 accesskey id
        :param _user: 用户名 未指定则删除当前API accesskey所属用户的
        """

        if _user:
            resp = self.aws_iam_api.delete_access_key(UserName=_user, AccessKeyId=_access_key_id)
        else:
            resp = self.aws_iam_api.delete_access_key(AccessKeyId=_access_key_id)
        if resp['ResponseMetadata']['HTTPStatusCode'] == 200:
            return '删除成功'

