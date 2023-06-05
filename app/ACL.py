from app.models import yuming, username


class Acl:
    def __init__(self, _domain_name, _current_user):
        self._domain_name = _domain_name
        self._current_user = _current_user

    def batches_prod(self):  # 批处理
        if not username.objects.get(username=self._current_user).batches_prod:
            return False
        else:
            return True

    def apollo_prod(self):  # Apollo更新
        if not username.objects.get(username=self._current_user).apollo_prod:
            return False
        else:
            return True

    def icp_domain(self):  # 查询备案域名
        if not username.objects.get(username=self._current_user).icp_domain:
            return False
        else:
            return True

    def delssl(self):  # 删除证书
        if not username.objects.get(username=self._current_user).delssl_prod:
            return False
        else:
            return True

    def update_cloud_key(self):  # 更新云密钥
        if not username.objects.get(username=self._current_user).update_cloud_key_prod:
            return False
        else:
            return True

    def select_cloud_key(self):  # 查询云密钥
        if not username.objects.get(username=self._current_user).select_cloud_key_prod:
            return False
        else:
            return True

    def xgcdn(self):  # 修改cdn
        if yuming.objects.get(ym=self._domain_name).hj.hj == 'prod':
            if not username.objects.get(username=self._current_user).xgcdn_prod:
                return False
            return True
        else:
            if not username.objects.get(username=self._current_user).xgcdn:
                return False
            return True

    def tjcdn(self):  # 添加cdn
        if yuming.objects.get(ym=self._domain_name).hj.hj == 'prod':
            if not username.objects.get(username=self._current_user).tjcdn_prod:
                return False
            return True
        else:
            if not username.objects.get(username=self._current_user).tjcdn:
                return False
            return True

    def sccdn(self):  # 删除cdn
        if yuming.objects.get(ym=self._domain_name).hj.hj == 'prod':
            if not username.objects.get(username=self._current_user).sccdn_prod:
                return False
            return True
        else:
            if not username.objects.get(username=self._current_user).sccdn:
                return False
            return True

    def xgdns(self):  # 修改dns
        if yuming.objects.get(ym=self._domain_name).hj.hj == 'prod':
            if not username.objects.get(username=self._current_user).xgdns_prod:
                return False
            return True
        else:
            if not username.objects.get(username=self._current_user).xgdns:
                return False
            return True

    def cdnsource(self):  # 查看cdn源站
        if yuming.objects.get(ym=self._domain_name).hj.hj == 'prod':
            if not username.objects.get(username=self._current_user).cdnsource_prod:
                return False
            return True
        else:
            if not username.objects.get(username=self._current_user).cdnsource:
                return False
            return True

    def sxhc(self):  # 刷新缓存
        if yuming.objects.get(ym=self._domain_name).hj.hj == 'prod':
            if not username.objects.get(username=self._current_user).sxhc_prod:
                return False
            return True
        else:
            if not username.objects.get(username=self._current_user).sxhc:
                return False
            return True

    def scdomain(self):  # 删除域名
        if yuming.objects.get(ym=self._domain_name).hj.hj == 'prod':
            if not username.objects.get(username=self._current_user).sctjdomain_prod:
                return False
            return True
        else:
            if not username.objects.get(username=self._current_user).sctjdomain:
                return False
            return True

    def tjdomain(self):  # 添加域名
        if self._domain_name == 'prod':
            if not username.objects.get(username=self._current_user).sctjdomain_prod:
                return False
            return True
        else:
            if not username.objects.get(username=self._current_user).sctjdomain:
                return False
            return True

    def xgdomain(self):  # 修改域名
        if yuming.objects.get(ym=self._domain_name).hj.hj == 'prod':
            if not username.objects.get(username=self._current_user).xgdomain_prod:
                return False
            return True
        else:
            if not username.objects.get(username=self._current_user).xgdomain:
                return False
            return True
