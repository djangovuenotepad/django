from django.db import models
from Crypto.Cipher import DES3
import base64,hashlib
from django_otp.oath import totp
from django_otp.util import random_hex
from app.encrypt import EncryptDate
from app.encrypt import HashDate

class xiangmu(models.Model):
        xm = models.CharField(max_length=255,unique=True,verbose_name="项目")
        bh = models.CharField(max_length=255,unique=False,blank=True,verbose_name="编号")
        class Meta:
                    verbose_name = '项目'
                    verbose_name_plural = '项目'
        def __str__(self):
                          return self.xm
class huanjing(models.Model):
        _hj = models.CharField(max_length=255, unique=True, blank=True,null=True,verbose_name="环境")
        hj = models.CharField(max_length=255,unique=True,verbose_name="编号")
        class Meta:
                    verbose_name = '环境'
                    verbose_name_plural = '环境'
        def __str__(self):
                          return self._hj
class suoshuyewu(models.Model):
        ssyw = models.CharField(max_length=255,unique=True,verbose_name="所属业务")
        class Meta:
                    verbose_name = '所属业务'
                    verbose_name_plural = '所属业务'
        def __str__(self):
                          return self.ssyw
class ywlx(models.Model):
        ywlx = models.CharField(max_length=255,unique=True,verbose_name="业务类型")
        class Meta:
                    verbose_name = '业务类型'
                    verbose_name_plural = '业务类型'
        def __str__(self):
                          return self.ywlx

class jxs(models.Model):
        jxs = models.CharField(max_length=255,unique=True,verbose_name="DNS&CDN 账户")
        cs = models.CharField(max_length=255,unique=False,blank=True,verbose_name="厂商")
        admin_zh = models.CharField(max_length=255,unique=False,blank=True,verbose_name="主账号")
        admin_zh_id = models.CharField(max_length=255, unique=False,blank=True, verbose_name="主账号ID")
        zh = models.CharField(max_length=255,unique=False,blank=True,verbose_name="IAM账号")
        zh_id = models.CharField(max_length=255, unique=False, blank=True,verbose_name="IAM账号ID")
        gy = models.CharField(max_length=255,unique=False,blank=True,verbose_name="公钥")
        sy = models.CharField(max_length=255,unique=False,blank=True,verbose_name="私钥")
        acme = models.TextField(max_length=10000, blank=True, verbose_name="acme认证环境变量",help_text='export HUAWEICLOUD_Username_hwc="****"  ( 注：dnsapi以 dns_解析商名称.sh 命名,环境变量中 -. 转换为 _ )')
        is_tgs = models.BooleanField(unique=False, null=True, blank=True, verbose_name="是否为 托管商 账户")
        is_jxs = models.BooleanField(unique=False, null=True, blank=True, verbose_name="是否为 解析商 账户")
        is_cdn = models.BooleanField(unique=False, null=True, blank=True, verbose_name="是否为 CDN&云主机 账户")
        class Meta:
                    verbose_name = 'DNS&CDN 账户'
                    verbose_name_plural = 'DNS&CDN 账户'
        def __str__(self):
                          return self.jxs
        def save(self,*args,**kwargs):
            if self.pk == None or jxs.objects.get(id=self.id).acme != self.acme:
                eg = EncryptDate()  
                self.acme = eg.encrypt(self.acme)
            if self.pk == None or jxs.objects.get(id=self.id).gy != self.gy or jxs.objects.get(id=self.id).sy != self.sy:
                eg = EncryptDate() 
                self.gy = eg.encrypt(self.gy)
                eg = EncryptDate() 
                self.sy = eg.encrypt(self.sy)
            super(jxs,self).save(*args,**kwargs)
        def get_gy(self):
            eg = EncryptDate()
            return str(eg.decrypt(jxs.objects.get(id=self.id).gy))
        def get_sy(self):
            eg = EncryptDate()
            return str(eg.decrypt(jxs.objects.get(id=self.id).sy))
        def get_acme(self):
            eg = EncryptDate()
            return str(eg.decrypt(jxs.objects.get(id=self.id).acme))

class username(models.Model):
        username = models.CharField(max_length=255,unique=True,verbose_name="登录用户")
        password = models.CharField(max_length=255,verbose_name="密码")
        otp = models.CharField(max_length=200,default=random_hex(10),help_text='OTP密钥为 输入值的base32加密值',verbose_name="OTP认证")
        hj = models.ManyToManyField("huanjing",unique=False, blank=True, verbose_name="环境授权")
        sxhc = models.BooleanField(unique=False, null=True, blank=True,verbose_name="刷新CDN缓存")
        xgcdn = models.BooleanField(unique=False, null=True, blank=True,verbose_name="修改CDN解析信息")
        sccdn = models.BooleanField(unique=False, null=True, blank=True,verbose_name="删除CDN解析信息")
        tjcdn = models.BooleanField(unique=False, null=True, blank=True,verbose_name="添加CDN解析信息")
        cdnsource = models.BooleanField(unique=False, null=True, blank=True, verbose_name="查看CDN源站")
        xgdns = models.BooleanField(unique=False, null=True, blank=True,verbose_name="修改域名DNS解析值")
        xgdomain = models.BooleanField(unique=False, null=True, blank=True, verbose_name="修改域名信息")
        sctjdomain = models.BooleanField(unique=False, null=True, blank=True,verbose_name="删除&添加域名")
        sxhc_prod = models.BooleanField(unique=False, null=True, blank=True,verbose_name="prod__刷新CDN缓存")
        xgcdn_prod = models.BooleanField(unique=False, null=True, blank=True,verbose_name="prod__修改CDN解析信息")
        sccdn_prod = models.BooleanField(unique=False, null=True, blank=True,verbose_name="prod__删除CDN解析信息")
        tjcdn_prod = models.BooleanField(unique=False, null=True, blank=True,verbose_name="prod__添加CDN解析信息")
        cdnsource_prod = models.BooleanField(unique=False, null=True, blank=True, verbose_name="prod__查看CDN源站")
        xgdns_prod = models.BooleanField(unique=False, null=True, blank=True,verbose_name="prod__修改域名DNS解析值")
        xgdomain_prod = models.BooleanField(unique=False, null=True, blank=True, verbose_name="prod__修改域名信息")
        sctjdomain_prod = models.BooleanField(unique=False, null=True, blank=True,verbose_name="prod__删除&添加域名")
        delssl_prod = models.BooleanField(unique=False, null=True, blank=True, verbose_name="prod__删除证书")
        update_cloud_key_prod = models.BooleanField(unique=False, null=True, blank=True, verbose_name="prod__更新云厂密钥")
        select_cloud_key_prod = models.BooleanField(unique=False, null=True, blank=True, verbose_name="prod__查询云厂密钥")
        icp_domain = models.BooleanField(unique=False, null=True, blank=True, verbose_name="prod__检测任务权限")
        apollo_prod = models.BooleanField(unique=False, null=True, blank=True, verbose_name="prod__Apollo权限")
        batches_prod = models.BooleanField(unique=False, null=True, blank=True, verbose_name="prod__批处理")
        class Meta:
                    verbose_name = '登录用户&权限管理'
                    verbose_name_plural = '登录用户&权限管理'
        def __str__(self):
            return self.username
        def save(self,*args,**kwargs):
            if self.pk == None or username.objects.get(id=self.id).otp != self.otp:
                self.otp = EncryptDate().encrypt(base64.b32encode(self.otp.encode('utf8')).decode('utf8'))
            if self.pk == None or username.objects.get(id=self.id).password != self.password :
                self.password = HashDate().hashsc(self.password)
            super(username,self).save(*args,**kwargs)
        def get_token(self):
            return EncryptDate().decrypt(username.objects.get(id=self.id).otp)
        def verify_token(self, token):
           try:
               token = int(token)
           except ValueError:
                verified = False
           else:
               verified = any(totp(base64.b32decode(self.get_token().encode('utf-8')), drift=drift) == token for drift in [0, -1])
           return verified

class beian(models.Model):
        ba = models.CharField(max_length=255,unique=True,verbose_name="备案")
        bh = models.CharField(max_length=255,unique=False,blank=True,verbose_name="编号")
        class Meta:
                    verbose_name = '备案'
                    verbose_name_plural = '备案'
        def __str__(self):
                          return self.ba

class yumingzhuangtai(models.Model):
        ymzt = models.CharField(max_length=255,unique=True,verbose_name="域名状态")
        bh = models.CharField(max_length=255,unique=False,blank=True,verbose_name="编号")
        class Meta:
                    verbose_name = '域名状态'
                    verbose_name_plural = '域名状态'
        def __str__(self):
                          return self.ymzt

class cdn(models.Model):
        cdn = models.CharField(max_length=255,unique=True,blank=True,verbose_name="CDN&服务器信息")
        jxlx = models.CharField(max_length=255,unique=False,blank=True,verbose_name="解析类型")
        jxz = models.CharField(max_length=255,unique=False,blank=True,verbose_name="解析值")
        yzlx = models.CharField(max_length=255,unique=False,blank=True,verbose_name="源站类型")
        jxs = models.ForeignKey("jxs",on_delete=models.CASCADE,unique=False,null=True,blank=True,verbose_name="CDN&解析商同账户")
        bz = models.TextField(max_length=255,unique=False,blank=True,verbose_name="备注")
        ssl = models.TextField(max_length=10000, unique=False, blank=True, verbose_name="证书到期时间")
        source_ip = models.TextField(max_length=10000, unique=False, blank=True, verbose_name="回源IP")
        class Meta:
                    verbose_name = 'CDN&服务器解析值'
                    verbose_name_plural = 'CDN&服务器解析值'
        def __str__(self):
                          return self.cdn

class yuming(models.Model):
        ym = models.CharField(max_length=255,unique=True,verbose_name="域名")
        xm = models.ForeignKey(xiangmu,on_delete=models.PROTECT,verbose_name="项目")
        hj = models.ForeignKey("huanjing",on_delete=models.PROTECT,verbose_name="环境")
        tgs = models.ForeignKey("jxs",on_delete=models.PROTECT,related_name="tgs",verbose_name="域名托管商")
        jxs = models.ForeignKey("jxs",on_delete=models.PROTECT,verbose_name="域名解析商")
        sfba = models.ForeignKey("beian",unique=False,on_delete=models.PROTECT,verbose_name="是否备案")
        ssyw = models.ForeignKey("suoshuyewu",on_delete=models.PROTECT,verbose_name="所属业务")
        ywlx = models.ForeignKey("ywlx",on_delete=models.PROTECT,verbose_name="业务类型")
        ymzt = models.ForeignKey("yumingzhuangtai",on_delete=models.PROTECT,verbose_name="域名状态")
        cdn = models.ManyToManyField("cdn",blank=True,verbose_name="可解析的CDN/服务器")
        bz = models.TextField(max_length=10000,blank=True,verbose_name="备注")
        class Meta:
                    verbose_name = '域名'
                    verbose_name_plural = '域名'
        def __str__(self):
                          return self.ym

class  uhistory(models.Model):
    ym = models.CharField(max_length=255 , verbose_name="操作域名")
    user = models.CharField(max_length=100, blank=True, verbose_name="操作人")
    utime = models.PositiveIntegerField(blank=True, verbose_name="操作时间")
    uexec = models.TextField(max_length=50000, blank=True, verbose_name="执行命令详情")
    class Meta:
        verbose_name = '历史操作记录'
        verbose_name_plural = '历史操作记录'

    def __str__(self):
        return self.ym

class acmessl(models.Model):
        zsmc = models.CharField(max_length=255,unique=True,blank=True,verbose_name="证书名称")
        zsgym = models.CharField(max_length=255, blank=True, verbose_name="证书公用名")
        ymgs = models.CharField(max_length=255, blank=True, verbose_name="域名个数")
        ms = models.CharField(max_length=255, blank=True, verbose_name="描述")
        bfjg = models.CharField(max_length=255, blank=True, verbose_name="颁发机构")
        bfsj = models.CharField(max_length=255, blank=True, verbose_name="颁发时间")
        dqsj = models.CharField(max_length=255, blank=True, verbose_name="到期时间")
        zsbdym = models.TextField(max_length=10000, blank=True, verbose_name="证书绑定域名")
        cer = models.TextField(max_length=50000, blank=True, verbose_name="公钥")
        key = models.TextField(max_length=50000, blank=True, verbose_name="私钥")

        class Meta:
                    verbose_name = '证书'
                    verbose_name_plural = '证书'
        def __str__(self):
                          return self.zsmc


class icp(models.Model):
    check_time = models.CharField(max_length=255, blank=True, verbose_name="检测时间")
    icp = models.TextField(max_length=50000, blank=True, verbose_name="检测信息")

    class Meta:
        verbose_name = '备案域名检测'
        verbose_name_plural = '备案域名检测'

    def __str__(self):
        return self.check_time

class domain_expire(models.Model):
    check_time = models.CharField(max_length=255, blank=True, verbose_name="检测时间")
    expire = models.TextField(max_length=50000, blank=True, verbose_name="检测信息")

    class Meta:
        verbose_name = '域名到期检测'
        verbose_name_plural = '域名到期检测'

    def __str__(self):
        return self.check_time
class apollo(models.Model):
    xm = models.CharField(max_length=255, blank=True, verbose_name="项目")
    conf = models.TextField(max_length=50000, blank=True, verbose_name="Apollo 配置")

    class Meta:
        verbose_name = 'Apollo配置文件'
        verbose_name_plural = 'Apollo配置文件'

    def __str__(self):
        return self.xm

class apollo_history(models.Model):
    _time = models.CharField(max_length=255, blank=True, verbose_name="操作时间")
    _user = models.CharField(max_length=255, blank=True, verbose_name="操作人员")
    _exec = models.TextField(max_length=50000, blank=True, verbose_name="Apollo 操作记录")

    class Meta:
        verbose_name = 'Apollo 操作记录'
        verbose_name_plural = 'Apollo 操作记录'

    def __str__(self):
        return self._time
class ck(models.Model):
    ck = models.CharField(max_length=255, blank=True, verbose_name="运维工具调用ck")

    class Meta:
        verbose_name = '运维工具调用ck'
        verbose_name_plural = '运维工具调用ck'
    def __str__(self):
        return self.ck
class game_id(models.Model):
    edit_time = models.CharField(max_length=255, blank=True, verbose_name="编辑时间")
    game_id = models.TextField(max_length=50000, blank=True, verbose_name="游戏ID对应表")
    class Meta:
        verbose_name = '游戏ID对应表'
        verbose_name_plural = '游戏ID对应表'
    def __str__(self):
        return self.edit_time
class upload_switch(models.Model):
    name = models.CharField(max_length=255, blank=True, null=True,verbose_name="是否开启")
    switch = models.BooleanField(unique=False, null=True, blank=True,verbose_name="开关")
    class Meta:
        verbose_name = '上传功能开关'
        verbose_name_plural = '上传功能开关'
    def __str__(self):
        return self.name

class aws_waf_history(models.Model):
    waf = models.CharField(max_length=255, blank=True, verbose_name="AWS_WAF白名单历史记录")
    waf_data = models.TextField(max_length=50000, blank=True, verbose_name="数据详情")

    class Meta:
        verbose_name = 'AWS_WAF白名单历史记录'
        verbose_name_plural = 'AWS_WAF白名单历史记录'

    def __str__(self):
        return self.waf