from app.ACL import Acl
from django.core.cache import cache
from django.shortcuts import HttpResponse
from django.db.models import Prefetch
from six import BytesIO
from urllib import  parse
from django.http import JsonResponse, FileResponse
from app.models import *
from app.encrypt import HashDate
from OpenSSL import crypto
from cryptography import x509
from django_otp.util import random_hex
import app.aliapi as aliapi
import app.huaweiapi as huaweiapi
import app.tencentapi as tencentapi
import app.nameapi as nameapi
import app.godaddyapi as godaddyapi
import app.awsapi as awsapi
import app.wangsuapi as wangsuapi
import app.apolloapi as apolloapi
import re, ssl, socket, random, time, whois, json, os, tarfile, traceback, logging, qrcode, subprocess, requests

LOG_FORMAT = '%(asctime)s [%(module)s] %(levelname)s [%(lineno)d] %(message)s'
logging.basicConfig(level=logging.DEBUG, format=LOG_FORMAT)

def get_awswaf_account_list(request):
    if request.session.get("login", None) and request.method == "POST":
        try:
            if not Acl(None, request.session.get('user', '')).batches_prod():
                return JsonResponse({"msg": "403", "code": 5001}, safe=False)
            msg = []
            for i in jxs.objects.filter(cs='aws'):
                msg.append(i.jxs)
            return JsonResponse({"msg": msg, "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)
def query_awswaf(request):
    if request.session.get("login", None) and request.method == "POST":
        try:
            if not Acl(None, request.session.get('user', '')).batches_prod():
                return JsonResponse({"msg": "403", "code": 5001}, safe=False)
            msg = []
            aws_ipset = []
            locktoken = {}
            rqs = json.loads(request.body)
            _aws_account = rqs.get("aws_account_one",None)
            if not _aws_account:
                return JsonResponse({'msg': "请选择帐号", 'code': 5001}, safe=False)
            _aws = jxs.objects.get(jxs=_aws_account)
            gy = _aws.get_gy()
            sy = _aws.get_sy()
            aws_waf = awsapi.AWSWAFApi(gy,sy)
            ipsets = aws_waf.list_ip_sets()
            for ipset in ipsets['IPSets']:
                _get_ipset = aws_waf.get_ip_set(ipset['Name'], ipset['Id'])
                aws_ipset.append(ipset['Name'])
                locktoken[ipset['Name']] = _get_ipset['LockToken']
                for _ip in _get_ipset["IPSet"]['Addresses']:
                    msg.append({"account":_aws_account, "ipset":ipset['Name'],"ip":_ip })
            return JsonResponse({"msg": msg, "locktoken":locktoken, "aws_ipset":aws_ipset, "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)
def waf_add_ipset_ip(request):
    if request.session.get("login", None) and request.method == "POST":
        try:
            if not Acl(None, request.session.get('user', '')).batches_prod():
                return JsonResponse({"msg": "403", "code": 5001}, safe=False)
            rqs = json.loads(request.body)
            _aws_account = rqs.get("aws_account_one")
            _ipset = rqs.get("ipset")
            _ip = rqs.get("ip")
            if not _aws_account or not _ipset or not _ip:
                return JsonResponse({'msg': "请勿提交空值", 'code': 5001}, safe=False)
            _aws = jxs.objects.get(jxs=_aws_account)
            gy = _aws.get_gy()
            sy = _aws.get_sy()
            aws_waf = awsapi.AWSWAFApi(gy,sy)
            _list_ipsets = aws_waf.list_ip_sets()
            for i in _list_ipsets['IPSets']:
                if i['Name'] == _ipset:
                    _id = i['Id']
                    _locktoken = i['LockToken']
            _get_ipset = aws_waf.get_ip_set(_ipset, _id)
            _source_ip = _get_ipset['IPSet']['Addresses']
            _LockToken = _get_ipset['LockToken']
            new_ip_list = []
            for _new_ip in _ip.splitlines():
                if '/' not in _new_ip:
                    _new_ip += '/32'
                new_ip_list.append(_new_ip)
            _new_ipset_ip = new_ip_list + _source_ip
            ##介于数据库限制,白名单多层写入数据库
            _len = 1500
            _time = time.strftime("%F_%T", time.localtime(time.time()))
            if len(_new_ipset_ip) > _len:
                _r = len(_new_ipset_ip) // _len + 2
                _front = 0
                n = 0
                for i in range(1, _r):
                    n+=1
                    _name = f'{_aws_account}-{_ipset}-{_time}-{n}'
                    _back = i * _len
                    _data = '\n'.join(_new_ipset_ip[_front:_back])
                    aws_waf_history.objects.create(waf=_name,waf_data=_data)
                    _front = i * _len
            else:
                _name = f'{_aws_account}-{_ipset}-{_time}'
                aws_waf_history.objects.create(waf=_name, waf_data='\n'.join(_new_ipset_ip))
            update_ipset = aws_waf.update_ip_set(Name=_ipset, Id=_id, Addresses=_new_ipset_ip, LockToken=_LockToken,Description=_name)
            if update_ipset['ResponseMetadata']['HTTPStatusCode'] != 200:
                raise Exception(str(update_ipset))
            else:
                uhistory.objects.create(ym=f"aws_waf-{_aws_account}-{_ipset}", user=request.session.get('user', ''), utime=int(time.time()),
                                        uexec=f"白名单添加IP {str(_ip)}")
                return JsonResponse({'msg': "白名单添加IP 更新成功", 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)
def waf_delete_ipset_ip(request):
    if request.session.get("login", None) and request.method == "POST":
        try:
            if not Acl(None, request.session.get('user', '')).batches_prod():
                return JsonResponse({"msg": "403", "code": 5001}, safe=False)
            rqs = json.loads(request.body)
            _aws_account = rqs.get("aws_account_one")
            _ipset = rqs.get("ipset")
            _ip = rqs.get("ip")
            _aws = jxs.objects.get(jxs=_aws_account)
            gy = _aws.get_gy()
            sy = _aws.get_sy()
            aws_waf = awsapi.AWSWAFApi(gy,sy)
            _list_ipsets = aws_waf.list_ip_sets()
            for i in _list_ipsets['IPSets']:
                if i['Name'] == _ipset:
                    _id = i['Id']
                    _locktoken = i['LockToken']
            _get_ipset = aws_waf.get_ip_set(_ipset, _id)
            _source_ip = _get_ipset['IPSet']['Addresses']
            _LockToken = _get_ipset['LockToken']
            for _remove_ip in _ip.splitlines():
                if '/' not in _remove_ip:
                    _remove_ip += '/32'
                if _remove_ip in _source_ip:
                    _source_ip.remove(_remove_ip)
            _new_ipset_ip = _source_ip
            ##介于数据库限制,白名单多层写入数据库
            _len = 1500
            _time = time.strftime("%F_%T", time.localtime(time.time()))
            if len(_new_ipset_ip) > _len:
                _r = len(_new_ipset_ip) // _len + 2
                _front = 0
                n = 0
                for i in range(1, _r):
                    n+=1
                    _name = f'{_aws_account}-{_ipset}-{_time}-{n}'
                    _back = i * _len
                    _data = '\n'.join(_new_ipset_ip[_front:_back])
                    aws_waf_history.objects.create(waf=_name,waf_data=_data)
                    _front = i * _len
            else:
                _name = f'{_aws_account}-{_ipset}-{_time}'
                aws_waf_history.objects.create(waf=_name, waf_data='\n'.join(_new_ipset_ip))
            update_ipset = aws_waf.update_ip_set(Name=_ipset, Id=_id, Addresses=_new_ipset_ip, LockToken=_LockToken,Description=_name)
            if update_ipset['ResponseMetadata']['HTTPStatusCode'] != 200:
                raise Exception(str(update_ipset))
            else:
                uhistory.objects.create(ym=f"aws_waf-{_aws_account}-{_ipset}", user=request.session.get('user', ''), utime=int(time.time()),
                                        uexec=f"白名单删除IP {str(_ip)}")
                return JsonResponse({'msg': "白名单删除IP 更新成功", 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)
def get_game_name(request):
        try:
            _data = game_id.objects.last().game_id
            _data = json.loads(_data)
            if request.method == "POST":
                return JsonResponse({"msg": _data, "code": 200}, safe=False)
            all_data = []
            _cname = {"QP":"棋牌","DY":"电游","BY":"博雅","C":"C端赛博"}
            for project in _data:
                for i in _data[project]:
                    all_data.append({"project": _cname[project], "gameid": i, "name": _data[project][i]})
            return JsonResponse({"msg": all_data, "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
def edit_gameid(request):
    if request.session.get("login", None):
        try:
            _msg = json.loads(request.body)
            if not _msg.get("gameid", '').strip() or not  _msg.get("gamename", '').strip():
                return JsonResponse({"msg": "请勿填写空值！", "code": 5001}, safe=False)
            _all_game_id = game_id.objects.last().game_id
            all_game_id = json.loads(_all_game_id)
            all_game_id[_msg['project']][_msg['gameid']] = _msg['gamename']
            _time = time.strftime("%F_%T", time.localtime(time.time()))
            game_id.objects.create(edit_time=_time, game_id=json.dumps(all_game_id))
            return JsonResponse({"msg": "更新成功", "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)
def ssh_deny_log(request):
    if request.session.get("login", None):
        try:
            _msg = json.loads(request.body)
            _day = _msg.get('day',7)
            data = requests.post("http://ssh_deny_log.com/ssh_deny_log",data={"day":_day}).content
            _data = json.loads(data)
            if _data['status'] == 200:
                if int(_day) == 0:
                    all_log = []
                    for i in _data['msg']:
                        t1 = i['信息'].split()[0]
                        t2 = i['信息'].split()[1]
                        ssh_deny_time = time.mktime(time.strptime(f'{t1}{t2}', "%Y-%m-%d%H:%M:%S"))
                        if time.time() - ssh_deny_time < 3600:
                            all_log.append(i)
                    return JsonResponse({"msg": all_log, "code": 200}, safe=False)
                else:
                    all_log = []
                    for i in _data['msg']:
                        t1 = i['信息'].split()[0]
                        t2 = i['信息'].split()[1]
                        ssh_deny_time = time.mktime(time.strptime(f'{t1}{t2}', "%Y-%m-%d%H:%M:%S"))
                        if time.time() - ssh_deny_time < (60 * 60 * 24 * 7 ):
                            all_log.append(i)
                    return JsonResponse({"msg": all_log, "code": 200}, safe=False)
            else:
                return JsonResponse({"msg": f"脚本查询异常：jenkins服务器 {_data['msg']} ", "code": 5001}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)
def get_ck_api(request):
    try:
        _ck = ck.objects.last().ck
        return JsonResponse({"msg": _ck, "code": 200}, safe=False)
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
def add_ck_api(request):
    try:
        _msg = json.loads(request.body)
        _ck = _msg.get('ck')
        ck.objects.create(ck=_ck)
        return JsonResponse({"msg": "更改完成", "code": 200}, safe=False)
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)

def apollo_pull(request):
    if request.session.get("login", None):
        if not Acl(None, request.session.get('user', '')).apollo_prod():
            return JsonResponse({"msg": "查询失败 权限拒绝！", "code": 5001}, safe=False)
        try:
            data = {}
            for xm in apollo.objects.filter():
                conf = json.loads(xm.conf)
                _apollo_data = apolloapi.pull(conf['token'], f"{conf['domain']}", conf['env'], conf['appId'])
                project_data = []
                for _key in _apollo_data:
                    if _key['key'] in conf['key']:
                        project_data.append({"xm": xm.xm, "key": _key['key'], "value": _key['value'],
                                             "last": _key['dataChangeLastModifiedTime'][:19].replace('T', ' '),
                                             "comment": _key.get('comment', None)})
                data[conf['xm']] = project_data
            return JsonResponse({"msg": data, "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)

def apollo_edit(request):
    if request.session.get("login", None) and request.method == "POST":
        if not Acl(None, request.session.get('user', '')).apollo_prod():
            return JsonResponse({"msg": "修改失败 权限拒绝！", "code": 5001}, safe=False)
        try:
            mess = json.loads(request.body)
            xm = mess.get('xm')
            key= mess.get('key')
            value = mess.get('value')
            comment = mess.get('comment',None)
            _conf = apollo.objects.get(xm=xm)
            _xm_conf = json.loads(_conf.conf)
            _token = _xm_conf['token']
            portal_address = _xm_conf['domain']
            env = _xm_conf['env']
            appId = _xm_conf['appId']
            status = apolloapi.edit(_token, portal_address, env, appId, key,value,comment)
            if status == 200:
                apollo_history.objects.create(_time=int(time.time()), _user=request.session.get('user', ''),
                                              _exec=f"修改项目: {xm}   键: {key}   值: {value}  备注: {comment}")
                return JsonResponse({"msg": f"修改成功", "code": 200}, safe=False)
            else:
                logging.debug(str(status))
                return JsonResponse({"msg": f"修改失败 {str(status)}", "code": 5001}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def apollo_release(request):
    if request.session.get("login", None) and request.method == "POST":
        if not Acl(None, request.session.get('user', '')).apollo_prod():
            return JsonResponse({"msg": "发布失败 权限拒绝！", "code": 5001}, safe=False)
        try:
            mess = json.loads(request.body)
            xm = mess.get('xm')
            _conf = apollo.objects.get(xm=xm)
            _xm_conf = json.loads(_conf.conf)
            _token = _xm_conf['token']
            portal_address = _xm_conf['domain']
            env = _xm_conf['env']
            appId = _xm_conf['appId']
            status = apolloapi.release(_token, portal_address, env, appId)
            if status == 200:
                apollo_history.objects.create(_time=int(time.time()), _user=request.session.get('user', ''),
                                              _exec=f"发布项目:  {xm}")
                return JsonResponse({"msg": f"发布成功", "code": 200}, safe=False)
            else:
                logging.debug(str(status))
                return JsonResponse({"msg": f"发布失败 {str(status)}", "code": 5001}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)

def apollo_history_log(request):
    if request.session.get("login", None) and request.method == "POST":
        if not Acl(None, request.session.get('user', '')).apollo_prod():
            return JsonResponse({"msg": "查询失败 权限拒绝！", "code": 5001}, safe=False)
        try:
            data = []
            for i in apollo_history.objects.filter():
                _time = time.strftime("%F %T",time.localtime(float(i._time)))
                data.append({"time":_time, "user": i._user, "exec": str(i._exec)})
            data.reverse()
            return JsonResponse({"msg": data, "code": 200}, safe=False)

        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def reload_opsweb(request):
    if request.session.get("login", None):
        try:
            os.system("supervisorctl reload")
            html_content = "<html><head><title>opsweb</title><script type='text/javascript'> setTimeout('window.history.go(-1)',10000)</script></head>"
            html_content += "<body><center><h1>opsweb 重启中·····</h1></center></body></html>"
            return HttpResponse(html_content)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)

def get_domain_expire(request):
    if request.session.get("login", None) and request.method == "POST":
        if not Acl(None, request.session.get('user', '')).icp_domain():
            return JsonResponse({"msg": "查询失败 权限拒绝！", "code": 5001}, safe=False)
        try:
            _data = json.loads(domain_expire.objects.last().expire)
            return JsonResponse({"msg": _data, "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def get_all_domain(request):
    if request.method == "POST":
        try:
            mess = json.loads(request.body)
            opskey = mess.get('opskey')
            hashwd = username.objects.get(username='api').password
            if not HashDate().hashpd(opskey, hashwd) or opskey is None:
                return JsonResponse("opskey 无效！", status=403, safe=False)
            _data = []
            for i in yuming.objects.select_related('jxs').filter():
                if i.jxs.jxs != '办公室dns':
                    i = i.ym.split(':')[0]
                    i = f"{i.split('.')[-2]}.{i.split('.')[-1]}"
                    _data.append(i)
            domains = list(set(_data))
            return JsonResponse({"msg": domains, "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def update_domain_expire(request):
    if request.method == "POST":
        try:
            mess = json.loads(request.body)
            opskey = mess.get('opskey')
            data = mess.get('data')
            hashwd = username.objects.get(username='api').password
            if not HashDate().hashpd(opskey, hashwd) or opskey is None:
                return JsonResponse("opskey 无效！", status=403, safe=False)
            _time = time.strftime("%F %T", time.localtime(time.time()))
            domain_expire.objects.create(check_time=_time, expire=json.dumps(data))
            return JsonResponse({"msg": "域名到期检测信息更新成功", "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def query_icp_status(request):
    if request.method == "POST":
        try:
            mess = json.loads(request.body)
            domains = mess.get("domain")
            query_icp_url = "http://check.icp.com:2080/query?domain="
            data = []
            for i in domains.split("\n"):
                if i:
                    check_status = requests.get(f"{query_icp_url}{i}").json()
                    for _check_frequency in range(0, 10):
                        if check_status.get("code") == -1:
                            print(time.strftime("%F_%Hh_%Mm", time.localtime(time.time())), f"域名{i} 查询频繁暂停10秒")
                            time.sleep(10)
                            check_status = requests.get(f"{query_icp_url}{i}").json()
                        else:
                            print(time.strftime("%F_%Hh_%Mm", time.localtime(time.time())), i, check_status)
                            break
                    if check_status.get("code") == -1:
                        data.append({'domain': i, 'icp_status': False, 'status': "查询频繁！！", 'check_time': time.time(),
                                     "mainLicence": None})
                    elif check_status.get('data')['isRecorded']:
                        data.append({'domain': i, 'icp_status': True, 'status': "正常", 'check_time': time.time(),
                                     "mainLicence": check_status.get('data')['mainLicence']})
                    else:
                        data.append({'domain': i, 'icp_status': False, 'status': "未备案", 'check_time': time.time(),
                                     "mainLicence": None})
                    time.sleep(2)
            return JsonResponse({"msg": data, "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def update_icp_domains(request):
    if request.method == "POST":
        try:
            mess = json.loads(request.body)
            opskey = mess.get('opskey')
            data = mess.get('data')
            hashwd = username.objects.get(username='api').password
            if not HashDate().hashpd(opskey, hashwd) or opskey is None:
                return JsonResponse("opskey 无效！", status=403, safe=False)
            _time = time.strftime("%F %T", time.localtime(time.time()))
            icp.objects.create(check_time=_time, icp=json.dumps(data))
            return JsonResponse({"msg": f"{_time} 备案信息更新成功", "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def get_icp_status(request):
    if request.session.get("login", None):
        if not Acl(None, request.session.get('user', '')).icp_domain():
            return JsonResponse({"msg": "查询失败 权限拒绝！", "code": 5001}, safe=False)
        try:
            _icp = json.loads(icp.objects.last().icp)
            if _icp:
                data = []
                for i in _icp:
                    if not _icp[i].get("icp_status"):
                        check_time_color = "red"
                    elif (time.time() - _icp[i]['check_time']) > 22000:
                        check_time_color = "yellow"
                    else:
                        check_time_color = "blue"
                    check_time = time.strftime("%F %T", time.localtime(_icp[i]['check_time']))
                    mainLicence = _icp[i].get('mainLicence')
                    icp_status = "正常" if _icp[i].get('icp_status') else "备案检测异常"
                    data.append({"domain": i, "icp_status": icp_status, "check_time_color": check_time_color,
                                 "check_time": check_time,
                                 "mainLicence": mainLicence})
                return JsonResponse({"msg": data, "code": 200}, safe=False)
            else:
                return JsonResponse({"msg": "暂无数据", "code": 5002}, safe=False)

        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def get_icp_status_last(request):
    ''' 获取单个备案域名最后一次检测的信息'''
    if request.method == "POST":
        try:
            mess = json.loads(request.body)
            opskey = mess.get('opskey')
            domain = mess.get("domain")
            hashwd = username.objects.get(username='api').password
            if not HashDate().hashpd(opskey, hashwd) or opskey is None:
                return JsonResponse("opskey 无效！", status=403, safe=False)
            data = icp.objects.last()
            if data:
                return JsonResponse({"msg": json.loads(data.icp).get(domain), "code": 200}, safe=False)
            else:
                return JsonResponse({"msg": '', "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def get_icp_domains(request):
    if request.method == "POST":
        try:
            mess = json.loads(request.body)
            opskey = mess.get('opskey')
            hashwd = username.objects.get(username='api').password
            if not HashDate().hashpd(opskey, hashwd) or opskey is None:
                return JsonResponse("opskey 无效！", status=403, safe=False)
            data = []
            for i in yuming.objects.filter(sfba=2):
                i = i.ym.split(":")[0]
                i = "{}.{}".format(i.split(".")[-2], i.split(".")[-1])
                data.append(i)
            return JsonResponse({"msg": list(set(data)), "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def fanchaxun(request):
    if request.method == "POST":
        try:
            data1 = "<h1>域名</h1>"
            mess = json.loads(request.body)
            domains = mess.get("domain")
            alldomaincdn = []
            for i in domains.split("\n"):
                if i.strip():
                    i = i.replace("*.", "")
                    _all_domain = yuming.objects.select_related("xm", "ymzt", "jxs").prefetch_related(
                        Prefetch('cdn', queryset=cdn.objects.filter().select_related('jxs'))).filter(
                        ym__contains=i,hj__in=[i.id for i in username.objects.get( username=request.session.get( 'user','')).hj.all()])
                    for _domain in _all_domain:
                        alldomaincdn.append(_domain)
                        data1 += f"{_domain.ym}<br>"
            data2 = "<h1>域名解析记录</h1>"
            allcdn = []
            for i in alldomaincdn:
                data2 += f"<h4><font color='read'>{i.ym}&nbsp;&nbsp;&nbsp;&nbsp;{i.xm.bh}</font></h4>"
                for _cdn in i.cdn.all():
                    data2 += f"{_cdn.jxs.jxs}&nbsp;&nbsp;{_cdn.jxz}<br>"
                    allcdn.append(_cdn.jxs.jxs)
            data3 = f"<h1>解析记录包含的CDN</h1>"
            for i in list(set(allcdn)):
                data3 += f"<h4>{i}<br></h4>"
            return JsonResponse({"msg1": data1, "msg2": data2, "msg3": data3, "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def update_ssl(request):
    if request.method == "POST":
        try:
            p = subprocess.Popen('/root/.virtualenvs/django-opsweb/bin/python3.9 /data/django-opsweb/script/证书检测.py ',
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0, universal_newlines=True,
                                 shell=True)
            while p.poll() is None:
                line = p.stdout.readline()
                pass
            return JsonResponse({"msg": "更新成功", "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def update_dns_ssl(request):
    if request.method == "POST":
        try:
            mess = json.loads(request.body)
            opskey = mess.get('opskey')
            hashwd = username.objects.get(username='api').password
            if not HashDate().hashpd(opskey, hashwd) or opskey is None:
                return JsonResponse("opskey 无效！", status=403, safe=False)
            _id = mess.get('id')
            _start = mess.get('start')
            _end = mess.get('end')
            _check_time = mess.get("check_time")
            _status = mess.get("status")
            _days = mess.get("days")
            _cdn = cdn.objects.get(id=int(_id))
            if _status == True:
                _cdn.ssl = json.dumps(
                    {"ssl_time": {"start": _start, "end": _end}, "status": _status, "days": _days,
                     "check_time": _check_time})
                _cdn.save()
            else:
                if _cdn.ssl:
                    before_check_time = json.loads(_cdn.ssl).get('check_time')
                    if (_check_time - before_check_time) > 259200:
                        now_cdn_ssl = json.loads(_cdn.ssl)
                        now_cdn_ssl['status'] = _status
                        _cdn.ssl = json.dumps(now_cdn_ssl)
                        _cdn.save()
                    else:
                        return JsonResponse({"msg": "三天以内忽略本次错误更新", "code": 200}, safe=False)
                else:
                    _cdn.ssl = json.dumps(
                        {"ssl_time": {"start": _start, "end": _end}, "status": None, "days": _days,
                         "check_time": _check_time})
                    _cdn.save()
            return JsonResponse({"msg": "ssl信息更新成功", "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def get_alldns(request):
    if request.method == "POST":
        try:
            mess = json.loads(request.body)
            opskey = mess.get('opskey')
            hashwd = username.objects.get(username='api').password
            if not HashDate().hashpd(opskey, hashwd) or opskey is None:
                return JsonResponse("opskey 无效！", status=403, safe=False)
            data = {}
            for i in yuming.objects.prefetch_related(
                    Prefetch('cdn', queryset=cdn.objects.filter().select_related('jxs'))).filter():
                for _cdn in i.cdn.all():
                    data[str(_cdn.id)] = {"domain": i.ym, "cdn_vendor": _cdn.jxs.jxs, "dns": _cdn.jxz,
                                          "source_ip": _cdn.source_ip}
            return JsonResponse({"msg": data, "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def get_alldns_ssl(request):
    if request.session.get("login", None) and request.method == "POST":
        try:
            data = []
            for i in yuming.objects.prefetch_related(
                    Prefetch('cdn', queryset=cdn.objects.filter().select_related('jxs'))).filter(
                hj__in=[i.id for i in username.objects.get(username=request.session.get('user', '')).hj.all()]):
                for _cdn in i.cdn.all():
                    if _cdn.ssl:
                        _ssl = json.loads(_cdn.ssl)
                        data.append({"domain": i.ym,
                                     "cdn": _cdn.jxs.jxs,
                                     "cname": _cdn.jxz,
                                     "start": _ssl.get('ssl_time').get("start"),
                                     "end": _ssl.get('ssl_time').get("end"),
                                     "days": _ssl.get("days"),
                                     "check_time": time.strftime("%F %T", time.localtime(_ssl.get("check_time"))),
                                     "latest":
                                         "success" if _ssl.get("status") and _ssl.get("check_time") and (
                                                 time.time() - _ssl.get('check_time')) < 259200 and _ssl.get(
                                             "days") and int(_ssl.get("days")) >= 15 else "warning"
                                     })

            return JsonResponse({"msg": data, "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def updateotp(request):
    if request.session.get("login", None) and request.method == "POST":
        try:
            _user = request.session.get('user', '')
            _user_t = username.objects.get(username=_user)
            _user_t.otp = random_hex(10)
            _user_t.save()
            return JsonResponse({"msg": "OTP 更新成功", "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def otptoken(request):
    if request.session.get("login", None) and request.method == "POST":
        try:
            _user = request.session.get('user', '')
            _user_token = username.objects.get(username=_user).get_token()
            return JsonResponse({"msg": _user_token, "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def otpqrcode(request):
    if request.session.get("login", None):
        _user = request.session.get('user', '')
        _user_token = username.objects.get(username=_user).get_token()
        url = f'otpauth://totp/opsweb_{_user}?secret={_user_token}'
        img = qrcode.make(url)
        buf = BytesIO()
        img.save(buf)
        image_stream = buf.getvalue()
        response = HttpResponse(image_stream, content_type="image/jpg")
        return response
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def logs(request):
    if request.session.get("login", None):
        with open('/data/django-opsweb/opsweb.log', 'r') as f:
            _logss = f.read()
        _logs = _logss.split('\n')
        _logs = _logs[-999:]
        _logs = _logs[::-1]
        msg = [{'log': i} for i in _logs]
        return JsonResponse({"msg": msg, "code": 200}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namesslread(request):
    if request.session.get("login", None):
        try:
            domain_name = request.GET['domain_name']
            c = ssl.create_default_context()
            s = c.wrap_socket(socket.socket(), server_hostname=domain_name.split(":")[0])
            if len(domain_name.split(":")) == 1:
                s.connect((domain_name, 443))
            else:
                s.connect((domain_name.split(":")[0], int(domain_name.split(":")[1])))
            cert = s.getpeercert()
            s.close()
            return JsonResponse({"msg": cert, "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namewhoisread(request):
    if request.session.get("login", None):
        try:
            domain_name = request.GET['domain_name']
            domain_name = domain_name.split(":")[0]
            return JsonResponse({"msg": whois.whois(domain_name), "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namednsbackupcreate(request):  # 添加CDN解析信息
    if request.session.get("login", None):
        mess = json.loads(request.body)
        _domain_name = mess['domain_name']
        _cdn_vendor = mess['cdn_vendor']
        _resolve_type = mess['resolve_type']
        _resolve_record = mess['resolve_record']
        _source_type = mess['source_type']
        _remarks = mess['remarks']
        _current_user = mess['current_user']
        if not Acl(_domain_name, _current_user).tjcdn():
            return JsonResponse({"msg": "添加失败 权限拒绝！", "code": 5001}, safe=False)
        try:
            cdn.objects.create(cdn=f'{_domain_name}  {_cdn_vendor}  {_resolve_type}  {_resolve_record}',
                               jxlx=_resolve_type, jxz=_resolve_record, bz=_remarks, \
                               yzlx=['伪装源' if _source_type == 0 else '真实源'][0], jxs=jxs.objects.get(jxs=_cdn_vendor))
            newcdn = cdn.objects.get(cdn=f'{_domain_name}  {_cdn_vendor}  {_resolve_type}  {_resolve_record}')
            yuming.objects.get(ym=_domain_name).cdn.add(newcdn)
            uhistory.objects.create(ym=_domain_name, user=_current_user, utime=int(time.time()),
                                    uexec=f"解析记录大全新增: {_cdn_vendor} {_resolve_record}")
            return JsonResponse({'msg': '添加成功', 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namednsbackupupdate(request):  # 更新CDN解析信息
    if request.session.get("login", None):
        mess = json.loads(request.body)
        _domain_name = mess['domain_name']
        _cdn_vendor = mess['cdn_vendor']
        _resolve_type = mess['resolve_type']
        _resolve_record = mess['resolve_record']
        _source_type = mess['source_type']
        _remarks = mess['remarks']
        _current_user = mess['current_user']
        if not Acl(_domain_name, _current_user).xgcdn():
            return JsonResponse({"msg": "更新失败 权限拒绝！", "code": 5001}, safe=False)
        try:
            his_mess = f'CDN信息:  {_resolve_record}  更新:  '
            if_hist = False
            oldcdn = cdn.objects.get(cdn__regex=f'^{_domain_name}.*{_resolve_record}$')
            if oldcdn.bz != _remarks:
                oldcdn.bz = _remarks
                his_mess += f' remarks:{_remarks}  '
                if_hist = True
            if oldcdn.yzlx != ('伪装源' if int(_source_type) == 0 else '真实源'):
                oldcdn.yzlx = '伪装源' if int(_source_type) == 0 else '真实源'
                his_mess += f' source_type:{_source_type}  '
                if_hist = True
            if oldcdn.jxs != jxs.objects.get(jxs=_cdn_vendor):
                oldcdn.jxs = jxs.objects.get(jxs=_cdn_vendor)
                his_mess += f' cdn_vendor:{_cdn_vendor}  '
                if_hist = True
            if not if_hist:
                return JsonResponse({'msg': '未更新内容', 'code': 5001}, safe=False)
            oldcdn.cdn = f'{_domain_name}  {_cdn_vendor}  {_resolve_type}  {_resolve_record}'
            oldcdn.save()
            uhistory.objects.create(ym=_domain_name, user=_current_user, utime=int(time.time()),
                                    uexec=f"{his_mess}")
            return JsonResponse({'msg': '更新成功', 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namednsbackupdelete(request):  # 删除CDN解析信息
    if request.session.get("login", None):
        mess = json.loads(request.body)
        _domain_name = mess['domain_name']
        _cdn_vendor = mess['cdn_vendor']
        _resolve_type = mess['resolve_type']
        _resolve_record = mess['resolve_record']
        _source_type = mess['source_type']
        _remarks = mess['remarks']
        _current_user = mess['current_user']
        if not Acl(_domain_name, _current_user).sccdn():
            return JsonResponse({"msg": "删除失败 权限拒绝！", "code": 5001}, safe=False)
        try:
            cdn.objects.get(cdn=f'{_domain_name}  {_cdn_vendor}  {_resolve_type}  {_resolve_record}').delete()
            uhistory.objects.create(ym=_domain_name, user=_current_user, utime=int(time.time()),
                                    uexec=f"解析记录大全删除:   {_cdn_vendor}  {_resolve_record}")
            return JsonResponse({'msg': '删除成功', 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)

    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namednsrecordadd(request):
    if request.session.get("login", None):
        mess = json.loads(request.body)
        item = json.loads(request.body)
        resolver = item.get('resolver')
        original_current_domain_name = item.get('current_doamin_name')
        _current_user = item.get('current_user')
        current_domain_name = original_current_domain_name.split(':')[0]
        if not Acl(original_current_domain_name, _current_user).xgdns():
            return JsonResponse({"msg": "更新失败 权限拒绝！", "code": 5001}, safe=False)
        if jxs.objects.get(jxs=resolver).cs == 'ali':
            _resolver = mess['resolver']
            csy = jxs.objects.get(jxs=_resolver).get_sy()
            cgy = jxs.objects.get(jxs=_resolver).get_gy()
            try:
                aliyun_dns_client = aliapi.AliyunDnsApi(cgy, csy)
                result = aliyun_dns_client.add_domain_dns_record(mess)
                uhistory.objects.create(ym=original_current_domain_name, user=_current_user, utime=int(time.time()),
                                        uexec=f"添加域名解析记录值：域名解析商：{resolver}，解析类型：{mess['Type']} ，解析值：{mess['Value']}")
                return JsonResponse(result, safe=False)
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)

        elif jxs.objects.get(jxs=resolver).cs == 'tencent':
            csy = jxs.objects.get(jxs=resolver).get_sy()
            cgy = jxs.objects.get(jxs=resolver).get_gy()
            try:
                tencent_dns_client = tencentapi.TencentCloudDnsApi(cgy, csy)
                msg = tencent_dns_client.add_domain_dns_record(item)
                uhistory.objects.create(ym=original_current_domain_name, user=request.session.get('user', ''),
                                        utime=int(time.time()),
                                        uexec=f"添加域名解析记录值：域名解析商：{resolver}，解析类型：{mess['Type']} ，解析值：{mess['current_doamin_name']}")
                return JsonResponse({'msg': msg, 'code': 200}, safe=False)
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)

        elif jxs.objects.get(jxs=resolver).cs == 'name':
            zh = jxs.objects.get(jxs=resolver).zh
            csy = jxs.objects.get(jxs=resolver).get_sy()
            try:
                name_come_dns_client = nameapi.NameComDnsApi(zh, csy, current_domain_name)
                msg = name_come_dns_client.add_domain_dns_record(item)
                uhistory.objects.create(ym=original_current_domain_name, user=request.session.get('user', ''),
                                        utime=int(time.time()),
                                        uexec=f"添加域名解析记录值：域名解析商：{resolver}，解析类型：{mess['type']} ，解析值：{mess['answer']}")
                return JsonResponse(msg, safe=False)
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
        else:
            return JsonResponse({'msg': "云商暂不支持删除", 'code': 5001}, safe=False)

    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namednsrecorddelete(request):
    if request.session.get("login", None):
        mess = json.loads(request.body)
        item = json.loads(request.body)
        resolver = item.get('resolver')
        original_current_domain_name = item.get('current_doamin_name')
        current_domain_name = original_current_domain_name.split(':')[0]
        if not Acl(original_current_domain_name, request.session.get('user', '')).xgdns():
            return JsonResponse({"msg": "更新失败 权限拒绝！", "code": 5001}, safe=False)
        if jxs.objects.get(jxs=resolver).cs == 'ali':
            _resolver = mess['resolver']
            csy = jxs.objects.get(jxs=_resolver).get_sy()
            cgy = jxs.objects.get(jxs=_resolver).get_gy()
            try:
                aliyun_dns_client = aliapi.AliyunDnsApi(cgy, csy)
                result = aliyun_dns_client.delete_domain_dns_record(mess)
                uhistory.objects.create(ym=original_current_domain_name, user=request.session.get('user', ''),
                                        utime=int(time.time()),
                                        uexec=f"删除域名解析记录值：域名解析商：{resolver}，解析类型：{mess['Type']} ，解析值：{mess['Value']}")
                return JsonResponse(result, safe=False)
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)

        elif jxs.objects.get(jxs=resolver).cs == 'tencent':
            csy = jxs.objects.get(jxs=resolver).get_sy()
            cgy = jxs.objects.get(jxs=resolver).get_gy()
            try:
                tencent_dns_client = tencentapi.TencentCloudDnsApi(cgy, csy)
                msg = tencent_dns_client.delete_domain_dns_record(item)
                uhistory.objects.create(ym=original_current_domain_name, user=request.session.get('user', ''),
                                        utime=int(time.time()),
                                        uexec=f"删除域名解析记录值：域名解析商：{resolver}，解析类型：{mess['Type']} ，解析值：{mess['current_doamin_name']}")
                return JsonResponse({'msg': msg, 'code': 200}, safe=False)
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)

        elif jxs.objects.get(jxs=resolver).cs == 'name':
            zh = jxs.objects.get(jxs=resolver).zh
            csy = jxs.objects.get(jxs=resolver).get_sy()
            try:
                name_come_dns_client = nameapi.NameComDnsApi(zh, csy, current_domain_name)
                msg = name_come_dns_client.delete_domain_dns_record(item)
                uhistory.objects.create(ym=original_current_domain_name, user=request.session.get('user', ''),
                                        utime=int(time.time()),
                                        uexec=f"删除域名解析记录值：域名解析商：{resolver}，解析类型：{mess['type']} ，解析值：{mess['answer']}")
                return JsonResponse(msg, safe=False)
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)

        else:
            return JsonResponse({'msg': "云商暂不支持删除", 'code': 5001}, safe=False)

    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)

def batches_replace_dns(request):      # 批处理：切换域名包含指定云商的DNS
    if request.session.get("login", None):
        _current_user = request.session.get('user', '')
        batches_domains_dns = json.loads(request.body)
        data = []
        if not Acl(None, request.session.get('user', '')).batches_prod():
            return JsonResponse({"msg": "修改失败 权限拒绝！", "code": 5001}, safe=False)
        for domain_dns in batches_domains_dns.get("domains"):
            batches_cloud_cdn_value_jxs = None
            batches_cloud_cdn_value_jxz = None
            batches_cloud_cdn_value_jxlx = None
            result = None
            batches_cloud_cdn = batches_domains_dns.get("cloud_cdn")
            resolver = domain_dns.get('resolver')
            _item = domain_dns.get('meta')
            original_current_domain_name = domain_dns.get('domain_name')
            current_domain_name = original_current_domain_name.split(':')[0]
            try:
                if domain_dns.get('cloud_cdn') not in batches_cloud_cdn:
                    result = "未匹配到可用CDN"
                    data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                                 "cloud_cdn": domain_dns.get('cloud_cdn'), "meta": domain_dns.get('meta'),
                                 "cloud_cdn_value": domain_dns.get("cloud_cdn_value"), "result": result})
                    continue
                if yuming.objects.get(ym=original_current_domain_name).ssyw.ssyw == 'cocos':
                    result = "cocos 保持不变"
                    data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                                 "cloud_cdn": domain_dns.get('cloud_cdn'), "meta": domain_dns.get('meta'),
                                 "cloud_cdn_value": domain_dns.get("cloud_cdn_value"), "result": result})
                    continue
                if len(_item) > 1:
                    result = "存在多个解析记录"
                    data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                                 "cloud_cdn": domain_dns.get('cloud_cdn'), "meta": domain_dns.get('meta'),
                                 "cloud_cdn_value": domain_dns.get("cloud_cdn_value"), "result": result})
                    continue

                else:
                    item = _item[0]
                for i in yuming.objects.prefetch_related(Prefetch('cdn', queryset=cdn.objects.filter().select_related('jxs'))).get(ym=original_current_domain_name).cdn.all():
                    if i.jxs.jxs not in batches_cloud_cdn:

                        batches_cloud_cdn_value_jxlx = i.jxlx.replace("A记录", 'A')
                        batches_cloud_cdn_value_jxz = i.jxz
                        batches_cloud_cdn_value_jxs = i.jxs.jxs

                if not batches_cloud_cdn_value_jxlx:
                    result = f"解析记录大全没匹配到可用CDN"
                    data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                                 "cloud_cdn": domain_dns.get('cloud_cdn'), "meta": domain_dns.get('meta'),
                                 "cloud_cdn_value": domain_dns.get("cloud_cdn_value"), "result": result})
                    continue
                if jxs.objects.get(jxs=resolver).cs == 'godaddy' and batches_cloud_cdn_value_jxlx == 'A':
                    result = f"godaddy 拒绝A记录 "
                    data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                                 "cloud_cdn": domain_dns.get('cloud_cdn'),"meta": domain_dns.get('meta'),
                                 "cloud_cdn_value": domain_dns.get("cloud_cdn_value"), "result": result})
                    continue
                if jxs.objects.get(jxs=resolver).cs == 'ali':
                    csy = jxs.objects.get(jxs=resolver).get_sy()
                    cgy = jxs.objects.get(jxs=resolver).get_gy()
                    try:
                        item['Type'] = batches_cloud_cdn_value_jxlx
                        item['Value'] = batches_cloud_cdn_value_jxz
                        aliyun_dns_client = aliapi.AliyunDnsApi(cgy, csy)
                        msg = aliyun_dns_client.update_domain_dns_record(item)
                        result = msg['msg']
                    except Exception as err:
                        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                        result = str(err)
                elif jxs.objects.get(jxs=resolver).cs == 'tencent':
                    csy = jxs.objects.get(jxs=resolver).get_sy()
                    cgy = jxs.objects.get(jxs=resolver).get_gy()
                    try:
                        tencent_dns_client = tencentapi.TencentCloudDnsApi(cgy, csy)
                        item['Type'] = batches_cloud_cdn_value_jxlx
                        item['Value'] = batches_cloud_cdn_value_jxz
                        msg = tencent_dns_client.update_domain_dns_record(item)
                        result = msg['msg']
                    except Exception as err:
                        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                        result = str(err)
                elif jxs.objects.get(jxs=resolver).cs == 'huawei':
                    csy = jxs.objects.get(jxs=resolver).get_sy()
                    cgy = jxs.objects.get(jxs=resolver).get_gy()
                    try:
                        whc_dns_client = huaweiapi.HwcDnsApi(key=cgy, secret=csy, domain_name=current_domain_name)
                        item['type'] = batches_cloud_cdn_value_jxlx
                        item['records'] = batches_cloud_cdn_value_jxz
                        msg = whc_dns_client.update_domain_dns_record(item)
                        result = msg['msg']
                    except Exception as err:
                        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                        result = str(err)
                elif jxs.objects.get(jxs=resolver).cs == 'name':
                    zh = jxs.objects.get(jxs=resolver).zh
                    csy = jxs.objects.get(jxs=resolver).get_sy()
                    try:
                        name_come_dns_client = nameapi.NameComDnsApi(zh, csy, current_domain_name)
                        item['type'] = batches_cloud_cdn_value_jxlx
                        item['answer'] = batches_cloud_cdn_value_jxz
                        msg = name_come_dns_client.update_domain_dns_record(item)
                        result = msg['msg']
                    except Exception as err:
                        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                        result = str(err)
                elif jxs.objects.get(jxs=resolver).cs == 'godaddy':
                    csy = jxs.objects.get(jxs=resolver).get_sy()
                    try:
                        godaddy_dns_client = godaddyapi.GodaddyDnsApi(csy, current_domain_name)
                        item['type'] = batches_cloud_cdn_value_jxlx
                        item['data'] = batches_cloud_cdn_value_jxz
                        msg = godaddy_dns_client.update_domain_dns_record(item)
                        result = msg['msg']
                    except Exception as err:
                        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                        result = str(err)
                data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                             "cloud_cdn": batches_cloud_cdn_value_jxs ,"meta": [item],
                             "cloud_cdn_value": batches_cloud_cdn_value_jxz, "result": result})
                uhistory.objects.create(ym=original_current_domain_name, user=request.session.get('user', ''), utime=int(time.time()),
                                        uexec=f"批处理修改DNS:  {batches_cloud_cdn_value_jxs}    {batches_cloud_cdn_value_jxz}")
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                             "cloud_cdn": domain_dns.get('cloud_cdn'), "meta": domain_dns.get('meta'),
                             "cloud_cdn_value": domain_dns.get("cloud_cdn_value"), "result": f"error: {str(err)}"})
        return JsonResponse({'msg': data, 'code': 200}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)



def batches_moddifying_dns(request):   # 批处理：域名dns解析值更新
    if request.session.get("login", None):
        _current_user = request.session.get('user', '')
        batches_domains_dns = json.loads(request.body)
        data = []
        if not Acl(None, request.session.get('user', '')).batches_prod():
            return JsonResponse({"msg": "修改失败 权限拒绝！", "code": 5001}, safe=False)
        for domain_dns in batches_domains_dns.get("domains"):
            batches_cloud_cdn_value_jxz = None
            batches_cloud_cdn_value_jxlx = None
            result = None
            batches_cloud_cdn = batches_domains_dns.get("cloud_cdn")
            resolver = domain_dns.get('resolver')
            _item = domain_dns.get('meta')
            original_current_domain_name = domain_dns.get('domain_name')
            current_domain_name = original_current_domain_name.split(':')[0]
            try:
                if batches_cloud_cdn == domain_dns.get('cloud_cdn'):
                    result = "保持不变"
                    data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                                 "cloud_cdn": domain_dns.get('cloud_cdn'), "meta": domain_dns.get('meta'),
                                 "cloud_cdn_value": domain_dns.get("cloud_cdn_value"), "result": result})
                    continue
                if yuming.objects.get(ym=original_current_domain_name).ssyw.ssyw == 'cocos':
                    result = "cocos 保持不变"
                    data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                                 "cloud_cdn": domain_dns.get('cloud_cdn'), "meta": domain_dns.get('meta'),
                                 "cloud_cdn_value": domain_dns.get("cloud_cdn_value"), "result": result})
                    continue
                if len(_item) > 1:
                    result = "存在多个解析记录"
                    data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                                 "cloud_cdn": domain_dns.get('cloud_cdn'),"meta": domain_dns.get('meta'),
                                 "cloud_cdn_value": domain_dns.get("cloud_cdn_value"), "result": result})
                    continue

                else:
                    item = _item[0]
                for i in yuming.objects.prefetch_related(Prefetch('cdn', queryset=cdn.objects.filter().select_related('jxs'))).get(ym=original_current_domain_name).cdn.all():
                    if i.jxs.jxs  == batches_cloud_cdn:
                        batches_cloud_cdn_value_jxlx = i.jxlx.replace("A记录",'A')
                        batches_cloud_cdn_value_jxz  = i.jxz
                if not batches_cloud_cdn_value_jxlx:
                    result = f"未匹配到 {batches_cloud_cdn} 解析值"
                    data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                                 "cloud_cdn": domain_dns.get('cloud_cdn'),"meta": domain_dns.get('meta'),
                                 "cloud_cdn_value": domain_dns.get("cloud_cdn_value"), "result": result})
                    continue
                if jxs.objects.get(jxs=resolver).cs == 'godaddy' and batches_cloud_cdn_value_jxlx == 'A':
                    result = f"godaddy 拒绝A记录 "
                    data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                                 "cloud_cdn": domain_dns.get('cloud_cdn'),"meta": domain_dns.get('meta'),
                                 "cloud_cdn_value": domain_dns.get("cloud_cdn_value"), "result": result})
                    continue
                if jxs.objects.get(jxs=resolver).cs == 'ali':
                    csy = jxs.objects.get(jxs=resolver).get_sy()
                    cgy = jxs.objects.get(jxs=resolver).get_gy()
                    try:
                        item['Type'] = batches_cloud_cdn_value_jxlx
                        item['Value'] = batches_cloud_cdn_value_jxz
                        aliyun_dns_client = aliapi.AliyunDnsApi(cgy, csy)
                        msg = aliyun_dns_client.update_domain_dns_record(item)
                        result = msg['msg']
                    except Exception as err:
                        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                        result = str(err)
                elif jxs.objects.get(jxs=resolver).cs == 'tencent':
                    csy = jxs.objects.get(jxs=resolver).get_sy()
                    cgy = jxs.objects.get(jxs=resolver).get_gy()
                    try:
                        tencent_dns_client = tencentapi.TencentCloudDnsApi(cgy, csy)
                        item['Type'] = batches_cloud_cdn_value_jxlx
                        item['Value'] = batches_cloud_cdn_value_jxz
                        msg = tencent_dns_client.update_domain_dns_record(item)
                        result = msg['msg']
                    except Exception as err:
                        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                        result = str(err)
                elif jxs.objects.get(jxs=resolver).cs == 'huawei':
                    csy = jxs.objects.get(jxs=resolver).get_sy()
                    cgy = jxs.objects.get(jxs=resolver).get_gy()
                    try:
                        whc_dns_client = huaweiapi.HwcDnsApi(key=cgy, secret=csy, domain_name=current_domain_name)
                        item['type'] = batches_cloud_cdn_value_jxlx
                        item['records'] = batches_cloud_cdn_value_jxz
                        msg = whc_dns_client.update_domain_dns_record(item)
                        result = msg['msg']
                    except Exception as err:
                        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                        result = str(err)
                elif jxs.objects.get(jxs=resolver).cs == 'name':
                    zh = jxs.objects.get(jxs=resolver).zh
                    csy = jxs.objects.get(jxs=resolver).get_sy()
                    try:
                        name_come_dns_client = nameapi.NameComDnsApi(zh, csy, current_domain_name)
                        item['type'] = batches_cloud_cdn_value_jxlx
                        item['answer'] = batches_cloud_cdn_value_jxz
                        msg = name_come_dns_client.update_domain_dns_record(item)
                        result = msg['msg']
                    except Exception as err:
                        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                        result = str(err)
                elif jxs.objects.get(jxs=resolver).cs == 'godaddy':
                    csy = jxs.objects.get(jxs=resolver).get_sy()
                    try:
                        godaddy_dns_client = godaddyapi.GodaddyDnsApi(csy, current_domain_name)
                        item['type'] = batches_cloud_cdn_value_jxlx
                        item['data'] = batches_cloud_cdn_value_jxz
                        msg = godaddy_dns_client.update_domain_dns_record(item)
                        result = msg['msg']
                    except Exception as err:
                        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                        result = str(err)
                data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                             "cloud_cdn": batches_cloud_cdn,"meta": [item],
                             "cloud_cdn_value": batches_cloud_cdn_value_jxz, "result": result})
                uhistory.objects.create(ym=original_current_domain_name, user=request.session.get('user', ''), utime=int(time.time()),
                                        uexec=f"批处理修改DNS:  {batches_cloud_cdn}    {batches_cloud_cdn_value_jxz}")
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                data.append({"domain_name": original_current_domain_name, "resolver": resolver,
                             "cloud_cdn": domain_dns.get('cloud_cdn'), "meta": domain_dns.get('meta'),
                             "cloud_cdn_value": domain_dns.get("cloud_cdn_value"), "result": f"error: {str(err)}"})
        return JsonResponse({'msg': data, 'code': 200}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namednsrecordupdate(request):  # 域名dns解析值更新
    if request.session.get("login", None):
        mess = json.loads(request.body)
        item = json.loads(request.body)
        resolver = item.get('resolver')
        original_current_domain_name = item.get('current_doamin_name')
        _current_user = item.get('current_user')
        current_domain_name = original_current_domain_name.split(':')[0]
        if not Acl(original_current_domain_name, _current_user).xgdns():
            return JsonResponse({"msg": "更新失败 权限拒绝！", "code": 5001}, safe=False)

        if jxs.objects.get(jxs=resolver).cs == 'ali':
            _resolver = mess['resolver']
            csy = jxs.objects.get(jxs=_resolver).get_sy()
            cgy = jxs.objects.get(jxs=_resolver).get_gy()
            try:
                aliyun_dns_client = aliapi.AliyunDnsApi(cgy, csy)
                msg = aliyun_dns_client.update_domain_dns_record(mess)
                uhistory.objects.create(ym=original_current_domain_name, user=_current_user, utime=int(time.time()),
                                        uexec=f"修改域名DNS解析值为: {mess['Value']}")
                return JsonResponse(msg, safe=False)
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
        elif jxs.objects.get(jxs=resolver).cs == 'tencent':
            csy = jxs.objects.get(jxs=resolver).get_sy()
            cgy = jxs.objects.get(jxs=resolver).get_gy()
            try:
                tencent_dns_client = tencentapi.TencentCloudDnsApi(cgy, csy)
                msg = tencent_dns_client.update_domain_dns_record(item)
                uhistory.objects.create(ym=original_current_domain_name, user=_current_user, utime=int(time.time()),
                                        uexec=f"修改域名DNS解析值为: {mess['current_doamin_name']}")
                return JsonResponse(msg, safe=False)
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
        elif jxs.objects.get(jxs=resolver).cs == 'huawei':
            csy = jxs.objects.get(jxs=resolver).get_sy()
            cgy = jxs.objects.get(jxs=resolver).get_gy()
            try:
                whc_dns_client = huaweiapi.HwcDnsApi(key=cgy, secret=csy, domain_name=current_domain_name)
                msg = whc_dns_client.update_domain_dns_record(item)
                uhistory.objects.create(ym=original_current_domain_name, user=_current_user, utime=int(time.time()),
                                        uexec=f"修改域名DNS解析值为: {mess['records']}")
                return JsonResponse(msg, safe=False)
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
        elif jxs.objects.get(jxs=resolver).cs == 'name':
            zh = jxs.objects.get(jxs=resolver).zh
            csy = jxs.objects.get(jxs=resolver).get_sy()
            try:
                name_come_dns_client = nameapi.NameComDnsApi(zh, csy, current_domain_name)
                msg = name_come_dns_client.update_domain_dns_record(item)
                uhistory.objects.create(ym=original_current_domain_name, user=_current_user, utime=int(time.time()),
                                        uexec=f"修改域名DNS解析值为: {mess['answer']}")
                return JsonResponse(msg, safe=False)
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
        elif jxs.objects.get(jxs=resolver).cs == 'godaddy':
            csy = jxs.objects.get(jxs=resolver).get_sy()
            try:
                godaddy_dns_client = godaddyapi.GodaddyDnsApi(csy, current_domain_name)
                msg = godaddy_dns_client.update_domain_dns_record(item)
                uhistory.objects.create(ym=original_current_domain_name, user=_current_user, utime=int(time.time()),
                                        uexec=f"修改域名DNS解析值为: {mess['data']}")
                return JsonResponse(msg, safe=False)
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)

    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def get_source_ip_data(request):
    if request.session.get("login", None) and request.method == "POST":
        try:
            if not Acl(None, request.session.get('user', '')).icp_domain():
                return JsonResponse({"msg": "查询失败 权限拒绝！", "code": 5001}, safe=False)
            mess = json.loads(request.body)
            _ip = mess.get("ip")
            _cname = mess.get("cname")
            if _cname and _ip:
                return JsonResponse({"msg": "只能选择一项", "code": 5001}, safe=False)
            data = []
            for i in yuming.objects.select_related('xm', 'hj', 'tgs', 'sfba', 'ssyw', 'ywlx', 'ymzt').prefetch_related(
                    Prefetch('cdn', queryset=cdn.objects.filter().select_related('jxs'))).filter():
                for _dns in i.cdn.all():
                    if _dns.jxs.jxs not in ['办公室dns']:
                        if _dns.source_ip:
                            source_ip = json.loads(_dns.source_ip)
                            _time = source_ip['time']
                            _data = source_ip['data']
                            data.append({"domain": i.ym, "project": i.xm.xm, "env": i.hj.hj, "ssyw": i.ssyw.ssyw,
                                         "cloud": _dns.jxs.jxs, "dns": _dns.jxz, "note": _dns.bz, "status": True,
                                         "source_ip": _data, "time": _time})
                        else:
                            data.append({"domain": i.ym, "project": i.xm.xm, "env": i.hj.hj, "ssyw": i.ssyw.ssyw,
                                         "cloud": _dns.jxs.jxs, "dns": _dns.jxz, "note": _dns.bz, "status": False,
                                         "source_ip": None, "time": None})
            if _ip:
                _source_info = []
                _data = []
                _copy_data = []
                for ipinfo in _ip.split('\n'):
                    if ipinfo:
                        for i in data:
                            if ipinfo in str(i.get('source_ip')):
                                _data.append(json.dumps(i))
                for i in set(_data):
                    _copy_data.append(json.loads(i)['domain'])
                    _source_info.append(json.loads(i))
                return JsonResponse({'msg': _source_info, 'copydata': '\n'.join(_copy_data), 'code': 200}, safe=False)
            if _cname:
                _source_info = []
                _data = []
                _copy_data = []
                for domaininfo in _cname.split('\n'):
                    if domaininfo:
                        for i in data:
                            if domaininfo == i.get('dns'):
                                _data.append(json.dumps(i))
                for i in set(_data):
                    _copy_data.append(json.loads(i)['domain'])
                    _source_info.append(json.loads(i))
                return JsonResponse({'msg': _source_info, 'copydata': '\n'.join(_copy_data), 'code': 200}, safe=False)
            return JsonResponse({'msg': data, 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def update_source_ip_data(request):
    if request.session.get("login", None) and request.method == "POST" or request.method == "PUT":
        try:
            _all_dns = []
            for i in yuming.objects.prefetch_related(
                    Prefetch('cdn', queryset=cdn.objects.filter().select_related('jxs'))).filter():
                for _cdn in i.cdn.all():
                    _all_dns.append({"domain_name": i.ym, "cdn_vendor": _cdn.jxs.jxs, "cname_value": _cdn.jxz})
            for _dns in _all_dns:
                try:
                    cjxs = _dns.get('cdn_vendor')
                    _domain = _dns.get("domain_name")
                    domain = _domain.split(":")[0]
                    cname_value = _dns.get("cname_value")
                    if jxs.objects.get(jxs=cjxs).cs == 'ali':
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        cgy = jxs.objects.get(jxs=cjxs).get_gy()
                        if aliapi.AliyunDcdnApi(cgy,csy).domain_in_dcdn(domain):
                            aliyun_dcdn_client = aliapi.AliyunDcdnApi(cgy, csy)
                            cloudmess = aliyun_dcdn_client.get_domain_dcdn_source_info(domain)
                        else:
                            aliyun_cdn_client = aliapi.AliyunCdnApi(cgy, csy)
                            cloudmess = aliyun_cdn_client.get_domain_cdn_source_info(domain)

                    elif jxs.objects.get(jxs=cjxs).cs == 'ali-gtm':
                        _cjxs = cjxs.replace("GTM-", '')
                        csy = jxs.objects.get(jxs=_cjxs).get_sy()
                        cgy = jxs.objects.get(jxs=_cjxs).get_gy()
                        aliyun_gtm_client = aliapi.AliGTMapi(cgy, csy)
                        _cname_value = cname_value.split('.')[0]
                        _cloudmess = aliyun_gtm_client.source_info(_cname_value)
                        cloudmess = {"msg": _cloudmess, "code": 200}

                    elif jxs.objects.get(jxs=cjxs).cs == 'huawei':
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        cgy = jxs.objects.get(jxs=cjxs).get_gy()
                        cloudmess = huaweiapi.HUAWEICDNConfig(domain, cgy, csy)

                    elif jxs.objects.get(jxs=cjxs).cs == 'huawei-waf':
                        _cjxs = cjxs.replace("WAF-", '')
                        csy = jxs.objects.get(jxs=_cjxs).get_sy()
                        cgy = jxs.objects.get(jxs=_cjxs).get_gy()
                        cloudmess = huaweiapi.Hwwaf(cgy, csy, domain).select_waf_source()

                    elif jxs.objects.get(jxs=cjxs).cs == 'tencent':
                        if yuming.objects.get(ym=domain).ssyw.ssyw not in ['gateway', ]:
                            csy = jxs.objects.get(jxs=cjxs).get_sy()
                            cgy = jxs.objects.get(jxs=cjxs).get_gy()
                            cloudmess = tencentapi.TENCENTCDNConfig(domain, cgy, csy)
                        else:
                            csy = jxs.objects.get(jxs=cjxs).get_sy()
                            cgy = jxs.objects.get(jxs=cjxs).get_gy()
                            cloudmess = tencentapi.TENCENTECDNConfig(domain, cgy, csy)

                    elif jxs.objects.get(jxs=cjxs).cs == 'aws':
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        cgy = jxs.objects.get(jxs=cjxs).get_gy()
                        aws_client = awsapi.AWSCDNApi(cgy, csy)
                        _cloudmess = aws_client.get_cdn_domain_source_info(domain)
                        cloudmess = {"msg": _cloudmess, "code": 200}

                    elif jxs.objects.get(jxs=cjxs).cs == 'wangsu':
                        zh = jxs.objects.get(jxs=cjxs).zh
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        wangsu_client = wangsuapi.WangsuCDNApi(zh, csy)
                        _cloudmess = wangsu_client.query_domain_config(domain, 'origin-config')
                        cloudmess = {"msg": _cloudmess, "code": 200}
                    else:
                        continue
                    if cloudmess.get("code") == 200:
                        logging.debug(cloudmess.get("msg"))
                        _source = {'time': time.strftime("%F %T", time.localtime(time.time())),
                                   "data": cloudmess.get("msg")}
                        for i in yuming.objects.prefetch_related(
                                Prefetch('cdn', queryset=cdn.objects.filter().select_related('jxs'))).get(
                            ym=_domain).cdn.all():
                            if i.jxz == cname_value and i.jxlx == "CNAME":
                                i.source_ip = json.dumps(_source)
                                i.save()
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": "更新完成", "code": 200}, safe=False)

        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namecdnsourcesInfo(request):  # 获取cdn源站信息
    try:
        if request.session.get("login", None) and request.method == "POST":
            mess = json.loads(request.body)
            _domain = mess["domain_name"]
            domain = _domain.split(":")[0]
            cjxs = mess["cdn_vendor"]
            cname_value = mess["cname_value"]
            if not Acl(_domain, request.session.get('user', '')).cdnsource():
                return JsonResponse({"msg": "查询失败 权限拒绝！", "code": 5001}, safe=False)
        elif request.method == "POST":
            mess = json.loads(request.body)
            opskey = mess.get('opskey')
            _domain = mess["domain_name"]
            domain = _domain.split(":")[0]
            cjxs = mess["cdn_vendor"]
            hashwd = username.objects.get(username='api').password
            if not HashDate().hashpd(opskey, hashwd) or opskey is None:
                return JsonResponse("opskey 无效！", status=403, safe=False)
        else:
            return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)

        if jxs.objects.get(jxs=cjxs).cs == 'ali':
            csy = jxs.objects.get(jxs=cjxs).get_sy()
            cgy = jxs.objects.get(jxs=cjxs).get_gy()
            if  aliapi.AliyunDcdnApi(cgy,csy).domain_in_dcdn(domain):
                aliyun_dcdn_client = aliapi.AliyunDcdnApi(cgy, csy)
                cloudmess = aliyun_dcdn_client.get_domain_dcdn_source_info(domain)
            else:
                aliyun_cdn_client = aliapi.AliyunCdnApi(cgy, csy)
                cloudmess = aliyun_cdn_client.get_domain_cdn_source_info(domain)

        elif jxs.objects.get(jxs=cjxs).cs == 'ali-gtm':
            _cjxs = cjxs.replace("GTM-", '')
            _cname_value = cname_value.split('.')[0]
            csy = jxs.objects.get(jxs=_cjxs).get_sy()
            cgy = jxs.objects.get(jxs=_cjxs).get_gy()
            aliyun_gtm_client = aliapi.AliGTMapi(cgy, csy)
            _cloudmess = aliyun_gtm_client.source_info(_cname_value)
            cloudmess = {"msg": _cloudmess, "code": 200}

        elif jxs.objects.get(jxs=cjxs).cs == 'huawei':
            csy = jxs.objects.get(jxs=cjxs).get_sy()
            cgy = jxs.objects.get(jxs=cjxs).get_gy()
            cloudmess = huaweiapi.HUAWEICDNConfig(domain, cgy, csy)

        elif jxs.objects.get(jxs=cjxs).cs == 'huawei-waf':
            _cjxs = cjxs.replace("WAF-", '')
            csy = jxs.objects.get(jxs=_cjxs).get_sy()
            cgy = jxs.objects.get(jxs=_cjxs).get_gy()
            cloudmess = huaweiapi.Hwwaf(cgy, csy, domain).select_waf_source()

        elif jxs.objects.get(jxs=cjxs).cs == 'tencent':
            if yuming.objects.get(ym=domain).ssyw.ssyw not in ['gateway', ]:
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                cgy = jxs.objects.get(jxs=cjxs).get_gy()
                cloudmess = tencentapi.TENCENTCDNConfig(domain, cgy, csy)
            else:
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                cgy = jxs.objects.get(jxs=cjxs).get_gy()
                cloudmess = tencentapi.TENCENTECDNConfig(domain, cgy, csy)

        elif jxs.objects.get(jxs=cjxs).cs == 'aws':
            try:
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                cgy = jxs.objects.get(jxs=cjxs).get_gy()
                aws_client = awsapi.AWSCDNApi(cgy, csy)
                _cloudmess = aws_client.get_cdn_domain_source_info(domain)
                cloudmess = {"msg": _cloudmess, "code": 200}
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                return JsonResponse({"msg": str(err), "code": 5001}, safe=False)

        elif jxs.objects.get(jxs=cjxs).cs == 'wangsu':
            try:
                zh = jxs.objects.get(jxs=cjxs).zh
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                wangsu_client = wangsuapi.WangsuCDNApi(zh, csy)
                _cloudmess = wangsu_client.query_domain_config(domain, 'origin-config')
                cloudmess = {"msg": _cloudmess, "code": 200}
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
        else:
            return JsonResponse({"msg": "不支持此云厂商", "code": 5001}, safe=False)

        if cloudmess.get('code') != 200:
            raise Exception(cloudmess.get('msg'))

        _source = {'time': time.strftime("%F %T", time.localtime(time.time())), "data": cloudmess.get("msg")}
        for i in yuming.objects.prefetch_related(
                Prefetch('cdn', queryset=cdn.objects.filter().select_related('jxs'))).get(
            ym=_domain).cdn.all():
            if i.jxz == cname_value:
                i.source_ip = json.dumps(_source)
                i.save()
        return JsonResponse(cloudmess, safe=False)
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)


def domain_namecdnrefresh(request):  # 刷新CDN缓存
    if request.session.get("login", None) and request.method == "POST":
        mess = json.loads(request.body)
        _domain = mess["domain_name"]
        _current_user = mess['current_user']
        domain = _domain.split(":")[0]
        uri = mess["uri"]
        url = f'https://{domain}{uri}'
        cjxs = mess["cdn_vendor"]
        if not uri.endswith('/'):
            return {'msg': '仅支持目录刷新,uri请以斜杠结尾', 'code': 5001}
        if not Acl(_domain, _current_user).sxhc():
            return JsonResponse({"msg": "刷新失败 权限拒绝！", "code": 5001}, safe=False)
        uhistory.objects.create(ym=_domain, user=_current_user, utime=int(time.time()),
                                uexec=f"刷新缓存    CDN: {cjxs}    URL: {url}    ")
        try:
            if jxs.objects.get(jxs=cjxs).cs == 'ali':
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                cgy = jxs.objects.get(jxs=cjxs).get_gy()
                if aliapi.AliyunDcdnApi(cgy, csy).domain_in_dcdn(domain):
                    aliyun_dcdn_client = aliapi.AliyunDcdnApi(cgy, csy)
                    cloudmess = aliyun_dcdn_client.exec_aliyun_dcdn_refresh_task(refresh_url=url,refresh_type="directory")
                    return JsonResponse({"msg": cloudmess, "refresh_url": url, "code": 200}, safe=False)
                else:
                    aliyun_cdn_client = aliapi.AliyunCdnApi(cgy, csy)
                    cloudmess = aliyun_cdn_client.exec_aliyun_cdn_refresh_task(refresh_url=url,
                                                                               refresh_type="directory")
                    return JsonResponse({"msg": cloudmess, "refresh_url": url, "code": 200}, safe=False)

            elif jxs.objects.get(jxs=cjxs).cs == 'huawei':
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                cgy = jxs.objects.get(jxs=cjxs).get_gy()
                hwc_cdn_client = huaweiapi.HwcCdnApi(cgy, csy, domain)
                cloudmess = hwc_cdn_client.exec_my_hwc_refresh_task(uri=uri)
                return JsonResponse({"msg": cloudmess, "refresh_url": url, "code": 200}, safe=False)

            elif jxs.objects.get(jxs=cjxs).cs == 'tencent':
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                cgy = jxs.objects.get(jxs=cjxs).get_gy()
                tencent_cdn_client = tencentapi.TencentCloudCdnApi(cgy, csy)
                cloudmess = tencent_cdn_client.exec_tencentcloud_cdn_refresh_task(refresh_url=url,
                                                                                  refresh_type="directory")
                return JsonResponse({"msg": cloudmess, "refresh_url": url, "code": 200}, safe=False)

            elif jxs.objects.get(jxs=cjxs).cs == 'aws':
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                cgy = jxs.objects.get(jxs=cjxs).get_gy()
                aws_client = awsapi.AWSCDNApi(cgy, csy)
                cloudmess = aws_client.exce_cdn_cache_refresh_task(domain, uri)
                return JsonResponse({"msg": cloudmess, "refresh_url": url, "code": 200}, safe=False)

            elif jxs.objects.get(jxs=cjxs).cs == 'wangsu':
                zh = jxs.objects.get(jxs=cjxs).zh
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                wangsu_client = wangsuapi.WangsuCDNApi(zh, csy)
                cloudmess = wangsu_client.exce_cdn_cache_refresh_task(domain, uri)
                return JsonResponse({"msg": cloudmess, "refresh_url": url, "code": 200}, safe=False)

            else:
                return JsonResponse({'msg': "云商暂不支持刷新", 'code': 5001}, safe=False)

        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": "刷新失败", "refresh_url": f"{url} {str(err)}", "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namecdnrefreshapi(request):  # API调用刷新CDN缓存
    if request.method == "POST":
        try:
            mess = json.loads(request.body)
            _ssyw = mess.get("business")
            _hj = mess.get("domain_env")
            _xm = mess.get("project")
            _ym = mess.get("domain")
            uri = mess.get("uri", '/')
            token = mess.get("token")
            hashwd = username.objects.get(username='refreshapi').password
            if not HashDate().hashpd(token, hashwd) or token is None:
                return JsonResponse({"msg": "token 认证失败", "code": 5001}, safe=False)
            if _ssyw and _hj and _xm:
                hjid = huanjing.objects.get(hj=_hj).id
                xmid = xiangmu.objects.get(bh=_xm).id
                ssywid = suoshuyewu.objects.get(ssyw=_ssyw).id
                all_domain = yuming.objects.filter(hj=hjid, xm=xmid, ssyw=ssywid, ymzt=2)
            elif _ym:
                all_domain = yuming.objects.filter(ym=_ym)
            else:
                return JsonResponse({"msg": "未识别的请求方式", "code": 5001}, safe=False)
            message = {}
            try:
                for domain in all_domain:
                    cjxs = domain.jxs.jxs
                    domain = domain.ym
                    _domain = domain
                    domain = domain.split(":")[0]
                    if jxs.objects.get(jxs=cjxs).cs == 'ali':
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        cgy = jxs.objects.get(jxs=cjxs).get_gy()
                        aliyun_dns_client = aliapi.AliyunDnsApi(cgy, csy)
                        cloudmess = aliyun_dns_client.get_domain_dns_record(domain)
                        meta = cloudmess.get('msg')
                        _value = cloudmess.get('msg')[0].get("Value")
                    elif jxs.objects.get(jxs=cjxs).cs == 'huawei':
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        cgy = jxs.objects.get(jxs=cjxs).get_gy()
                        hwc_dns_client = huaweiapi.HwcDnsApi(key=cgy, secret=csy, domain_name=domain)
                        cloudmess = hwc_dns_client.get_domain_dns_record()
                        _value = cloudmess.get('msg')[0].get("records")[0]
                    elif jxs.objects.get(jxs=cjxs).cs == 'name':
                        zh = jxs.objects.get(jxs=cjxs).zh
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        name_come_dns_client = nameapi.NameComDnsApi(zh, csy, domain)
                        cloudmess = name_come_dns_client.get_domain_dns_record()
                        _value = cloudmess.get('msg')[0].get('answer')
                    elif jxs.objects.get(jxs=cjxs).cs == 'godaddy':
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        godaddy_dns_client = godaddyapi.GodaddyDnsApi(csy, domain)
                        cloudmess = godaddy_dns_client.get_domain_dns_record()
                        _value = cloudmess.get('msg')[0].get('data')
                    elif jxs.objects.get(jxs=cjxs).cs == 'tencent':
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        cgy = jxs.objects.get(jxs=cjxs).get_gy()
                        tencent_dns_client = tencentapi.TencentCloudDnsApi(cgy, csy)
                        cloudmess = tencent_dns_client.get_domain_dns_record(domain)
                        _value = cloudmess.get('msg')[0].get("Value")
                    else:
                        message[domain] = "DNS查询 不支持此云厂商"

                    if re.findall('^gtm-', _value):
                        message[domain] = "GTM 无需刷新"
                        continue
                    if not uri.endswith('/'):
                        message[domain] = "uri 请以斜杠结尾"
                        continue
                    if yuming.objects.get(ym=_domain).ywlx.ywlx == '后端':
                        message[domain] = "后端域名 无需刷新"
                        continue
                    if _value.endswith('.'):
                        _value = _value[::-1].replace('.', '', 1)[::-1]

                    cdn_jxs = cdn.objects.filter(jxz=_value)[0].jxs.jxs
                    domain = domain.split(":")[0]
                    url = f'https://{domain}{uri}'

                    try:
                        if jxs.objects.get(jxs=cdn_jxs).cs == 'ali':
                            csy = jxs.objects.get(jxs=cjxs).get_sy()
                            cgy = jxs.objects.get(jxs=cjxs).get_gy()
                            if aliapi.AliyunDcdnApi(cgy, csy).domain_in_dcdn(domain):
                                aliyun_dcdn_client = aliapi.AliyunDcdnApi(cgy, csy)
                                cloudmess = aliyun_dcdn_client.exec_aliyun_dcdn_refresh_task(refresh_url=url,
                                                                                             refresh_type="directory")
                                message[domain] = cloudmess
                            else:
                                aliyun_cdn_client = aliapi.AliyunCdnApi(cgy, csy)
                                cloudmess = aliyun_cdn_client.exec_aliyun_cdn_refresh_task(refresh_url=url,
                                                                                           refresh_type="directory")
                                message[domain] = cloudmess

                        elif jxs.objects.get(jxs=cdn_jxs).cs == 'huawei':
                            csy = jxs.objects.get(jxs=cdn_jxs).get_sy()
                            cgy = jxs.objects.get(jxs=cdn_jxs).get_gy()
                            hwc_cdn_client = huaweiapi.HwcCdnApi(cgy, csy, domain)
                            cloudmess = hwc_cdn_client.exec_my_hwc_refresh_task(uri=uri)
                            message[domain] = cloudmess

                        elif jxs.objects.get(jxs=cdn_jxs).cs == 'tencent':
                            csy = jxs.objects.get(jxs=cdn_jxs).get_sy()
                            cgy = jxs.objects.get(jxs=cdn_jxs).get_gy()
                            tencent_cdn_client = tencentapi.TencentCloudCdnApi(cgy, csy)
                            cloudmess = tencent_cdn_client.exec_tencentcloud_cdn_refresh_task(refresh_url=url,
                                                                                              refresh_type="directory")
                            message[domain] = cloudmess

                        elif jxs.objects.get(jxs=cdn_jxs).cs == 'aws':
                            csy = jxs.objects.get(jxs=cdn_jxs).get_sy()
                            cgy = jxs.objects.get(jxs=cdn_jxs).get_gy()
                            aws_client = awsapi.AWSCDNApi(cgy, csy)
                            cloudmess = aws_client.exce_cdn_cache_refresh_task(domain, uri)
                            message[domain] = cloudmess

                        elif jxs.objects.get(jxs=cdn_jxs).cs == 'wangsu':
                            zh = jxs.objects.get(jxs=cdn_jxs).zh
                            csy = jxs.objects.get(jxs=cdn_jxs).get_sy()
                            wangsu_client = wangsuapi.WangsuCDNApi(zh, csy)
                            cloudmess = wangsu_client.exce_cdn_cache_refresh_task(domain, uri)
                            message[domain] = cloudmess
                        uhistory.objects.create(ym=domain, user="refreshapi", utime=int(time.time()),
                                                uexec=f"刷新缓存    CDN: {cdn_jxs}    URL: {url}    ")
                    except Exception as err:
                        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                        message[domain] = f"刷新失败  {str(err)}"
            except Exception as err:
                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                message['error'] = str(err)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
        return JsonResponse({"msg": message, "code": 200})
    else:
        return JsonResponse({"msg": "请求失败", "code": 200})

def batches_get_dns_msg(request):    #批处理： 批量获取DNS解析值
    if request.session.get("login", None):
        try:
            mess = json.loads(request.body)
            domains = mess["domains"]
            data = []
            for _domain in domains:
                domins_ = _domain
                _domain = domins_['domain_name'].split(":")[0]
                cjxs = domins_["resolver"]
                cloud_cdn_value = ''
                meta = ''
                try:
                    if jxs.objects.get(jxs=cjxs).cs == 'ali':
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        cgy = jxs.objects.get(jxs=cjxs).get_gy()
                        aliyun_dns_client = aliapi.AliyunDnsApi(cgy, csy)
                        cloudmess = aliyun_dns_client.get_domain_dns_record(_domain)
                        meta = cloudmess['msg']
                        cloud_cdn_value = cloudmess['msg'][0]['Value']
                    elif jxs.objects.get(jxs=cjxs).cs == 'huawei':
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        cgy = jxs.objects.get(jxs=cjxs).get_gy()
                        hwc_dns_client = huaweiapi.HwcDnsApi(key=cgy, secret=csy, domain_name=_domain)
                        cloudmess = hwc_dns_client.get_domain_dns_record()
                        meta = cloudmess['msg']
                        cloud_cdn_value = cloudmess['msg'][0]['records'][0]
                    elif jxs.objects.get(jxs=cjxs).cs == 'name':
                        zh = jxs.objects.get(jxs=cjxs).zh
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        name_come_dns_client = nameapi.NameComDnsApi(zh, csy, _domain)
                        cloudmess = name_come_dns_client.get_domain_dns_record()
                        meta = cloudmess['msg']
                        cloud_cdn_value = cloudmess['msg'][0]['answer']
                    elif jxs.objects.get(jxs=cjxs).cs == 'godaddy':
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        godaddy_dns_client = godaddyapi.GodaddyDnsApi(csy, _domain)
                        cloudmess = godaddy_dns_client.get_domain_dns_record()
                        meta = cloudmess['msg']
                        cloud_cdn_value = cloudmess['msg'][0]['data']
                    elif jxs.objects.get(jxs=cjxs).cs == 'tencent':
                        csy = jxs.objects.get(jxs=cjxs).get_sy()
                        cgy = jxs.objects.get(jxs=cjxs).get_gy()
                        tencent_dns_client = tencentapi.TencentCloudDnsApi(cgy, csy)
                        cloudmess = tencent_dns_client.get_domain_dns_record(_domain)
                        meta = cloudmess['msg']
                        cloud_cdn_value = cloudmess['msg'][0]['Value']
                    else:
                        cloud_cdn_value = "不支持查询"
                    if cloud_cdn_value.endswith('.'):
                        cloud_cdn_value = cloud_cdn_value[::-1].replace('.', '', 1)[::-1]
                    if cloud_cdn_value == "不支持查询":
                        cloud_cdn = cjxs
                    else:
                        cloud_cdn = cdn.objects.select_related("jxs").filter(jxz=cloud_cdn_value)[0].jxs.jxs
                    data.append({'domain_name': domins_['domain_name'], "cloud_cdn": cloud_cdn, "cloud_cdn_value": cloud_cdn_value, "resolver": cjxs, "meta":meta})
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                    data.append({'domain_name': domins_['domain_name'], "cloud_cdn": "获取失败", "cloud_cdn_value": cloud_cdn_value, "resolver": cjxs, "meta":meta})
            return JsonResponse({'msg': data, 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)

def domain_namednsrecordread(request):
    if request.session.get("login", None):
        try:
            mess = json.loads(request.body)
            _domain = mess["domain_name"]
            _domain = _domain.split(":")[0]
            cjxs = mess["resolver"]
            if jxs.objects.get(jxs=cjxs).cs == 'ali':
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                cgy = jxs.objects.get(jxs=cjxs).get_gy()
                aliyun_dns_client = aliapi.AliyunDnsApi(cgy, csy)
                cloudmess = aliyun_dns_client.get_domain_dns_record(_domain)
                return JsonResponse(cloudmess, safe=False)
            elif jxs.objects.get(jxs=cjxs).cs == 'huawei':
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                cgy = jxs.objects.get(jxs=cjxs).get_gy()
                hwc_dns_client = huaweiapi.HwcDnsApi(key=cgy, secret=csy, domain_name=_domain)
                cloudmess = hwc_dns_client.get_domain_dns_record()
                return JsonResponse(cloudmess, safe=False)
            elif jxs.objects.get(jxs=cjxs).cs == 'name':
                zh = jxs.objects.get(jxs=cjxs).zh
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                name_come_dns_client = nameapi.NameComDnsApi(zh, csy, _domain)
                cloudmess = name_come_dns_client.get_domain_dns_record()
                return JsonResponse(cloudmess, safe=False)
            elif jxs.objects.get(jxs=cjxs).cs == 'godaddy':
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                godaddy_dns_client = godaddyapi.GodaddyDnsApi(csy, _domain)
                cloudmess = godaddy_dns_client.get_domain_dns_record()
                return JsonResponse(cloudmess, safe=False)
            elif jxs.objects.get(jxs=cjxs).cs == 'tencent':
                csy = jxs.objects.get(jxs=cjxs).get_sy()
                cgy = jxs.objects.get(jxs=cjxs).get_gy()
                tencent_dns_client = tencentapi.TencentCloudDnsApi(cgy, csy)
                cloudmess = tencent_dns_client.get_domain_dns_record(_domain)
                return JsonResponse(cloudmess, safe=False)
            else:
                return JsonResponse({"msg": "不支持此云厂商", "code": 5001}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namednsbackupread(request):
    if request.session.get("login", None):
        try:
            domain_name = request.GET['domain_name']
            allmess = []
            for i in yuming.objects.get(ym=domain_name).cdn.all():
                allmess.append({"domain_name": domain_name,
                                "cdn_vendor": i.jxs.jxs,
                                "resolve_type": i.jxlx,
                                "resolve_record": i.jxz,
                                "source_type": 1 if i.yzlx == '真实源' else 0,
                                "remarks": i.bz,
                                "cdn_sources_config_loading": False})
            return JsonResponse({"msg": allmess, "code": 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def historyread5(request):
    if request.session.get("login", None):
        mess = json.loads(request.body)
        _domain_name = mess['domain_name']
        ulog = uhistory.objects.filter(ym=_domain_name)
        message = []
        if len(ulog) > 4:
            for i in list(ulog)[-5:]:
                message.append({
                    "domain_name": i.ym,
                    "details": i.uexec,
                    "operate_people": i.user,
                    "operate_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i.utime))
                }
                )
        else:
            for i in list(ulog):
                message.append({
                    "domain_name": i.ym,
                    "details": i.uexec,
                    "operate_people": i.user,
                    "operate_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i.utime))
                }
                )
        message.reverse()
        return JsonResponse({"msg": message, "code": 200})
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def historyread0(request):
    if request.session.get("login", None):
        mess = json.loads(request.body)
        message = []
        if mess.get('domain_name') and mess.get("operate_time_range"):
            select_time = mess.get("operate_time_range")
            select_time = json.loads(select_time)
            select_domain = mess.get('domain_name')
            for i in uhistory.objects.filter(ym=select_domain, utime__gt=select_time[0], utime__lt=select_time[1]):
                message.append({
                    "domain_name": i.ym,
                    "details": i.uexec,
                    "operate_people": i.user,
                    "operate_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i.utime))
                }
                )
            message.reverse()
            return JsonResponse({"msg": message, "code": 200})
        elif mess.get('domain_name'):
            select_domain = mess.get('domain_name')
            for i in uhistory.objects.filter(ym=select_domain):
                message.append({
                    "domain_name": i.ym,
                    "details": i.uexec,
                    "operate_people": i.user,
                    "operate_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i.utime))
                }
                )
            message.reverse()
            return JsonResponse({"msg": message, "code": 200})
        else:
            select_time = mess.get("operate_time_range")
            if not select_time:
                select_time = [time.time() - 60 * 60 * 24, time.time()]
            else:
                select_time = json.loads(select_time)
            for i in uhistory.objects.filter(utime__gt=select_time[0], utime__lt=select_time[1]):
                message.append({
                    "domain_name": i.ym,
                    "details": i.uexec,
                    "operate_people": i.user,
                    "operate_time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(i.utime))
                }
                )
            message.reverse()
            return JsonResponse({"msg": message, "code": 200})
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namebasic_infocreate(request):
    if request.session.get("login", None):
        mess = json.loads(request.body)
        domain_env = mess['domain_env']
        _current_user = mess['current_user']
        if not Acl(domain_env, _current_user).tjdomain():
            return JsonResponse({"msg": "添加失败 权限拒绝！", "code": 5001}, safe=False)
        try:
            yuming.objects.create(ym=mess['domain_name'], xm=xiangmu.objects.get(bh=mess['project']),
                                  hj=huanjing.objects.get(hj=mess['domain_env']),
                                  tgs=jxs.objects.get(jxs=mess['registar']),
                                  jxs=jxs.objects.get(jxs=mess['resolver']),
                                  sfba=beian.objects.get(bh=mess['is_beian']),
                                  ssyw=suoshuyewu.objects.get(ssyw=mess['business']),
                                  ywlx=ywlx.objects.get(ywlx=mess['business_type']),
                                  ymzt=yumingzhuangtai.objects.get(bh=mess['domain_status']), bz=mess['remarks'])
            uhistory.objects.create(ym=mess['domain_name'], user=mess['current_user'], utime=int(time.time()),
                                    uexec=f"添加域名")
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
        return JsonResponse({"msg": "添加记录成功", "code": 200}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def business_summary_inforead(request):
    if request.session.get("login", None):
        js = []
        for i in suoshuyewu.objects.filter():
            js.append(
                {"value": i.ssyw, "label": i.ssyw})
        return JsonResponse({'msg': js, 'code': 200}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def cloud_vendor_info_tgsread(request):
    if request.session.get("login", None):
        js = []
        for i in jxs.objects.filter(is_tgs=True):
            js.append(
                {"value": i.jxs, "label": i.jxs})
        return JsonResponse({'msg': js, 'code': 200}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def cloud_vendor_info_dnsread(request):
    if request.session.get("login", None):
        js = []
        for i in jxs.objects.filter(is_jxs=True):
            js.append(
                {"value": i.jxs, "label": i.jxs})
        return JsonResponse({'msg': js, 'code': 200}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def cloud_vendor_info_cdnread(request):
    if request.session.get("login", None):
        js = []
        for i in jxs.objects.filter(is_cdn=True):
            js.append(
                {"value": i.jxs, "label": i.jxs})
        return JsonResponse({'msg': js, 'code': 200}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def cloud_vendor_inforead(request):
    if request.session.get("login", None):
        js = []
        for i in jxs.objects.filter():
            js.append(
                {"value": i.jxs, "label": i.jxs})
        return JsonResponse({'msg': js, 'code': 200}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def project_inforead(request):
    if request.session.get("login", None):
        js = []
        for i in xiangmu.objects.filter():
            js.append(
                {"value": i.bh, "label": i.xm})
        return JsonResponse({'msg': js, 'code': 200}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namebasic_infoupdate(request):  # 更新域名信息
    if request.session.get("login", None):
        mess = json.loads(request.body)
        _domain_name = mess["domain_name"]
        _registar = mess["registar"]
        _resolver = mess["resolver"]
        _is_beian = mess["is_beian"]
        _project = mess["project"]
        _domain_env = mess["domain_env"]
        _business = mess["business"]
        _business_type = mess["business_type"]
        _domain_status = mess["domain_status"]
        _remarks = mess["remarks"]
        _current_user = mess["current_user"]

        if not yuming.objects.filter(ym=_domain_name):
            return JsonResponse({"msg": "更新失败 域名未找到！", "code": 5001}, safe=False)
        # 信息对比
        _new_mess = mess.copy()
        _new_mess.pop('domain_name')
        _new_mess.pop('current_user')
        _new_mess.pop('apollo')
        _old = yuming.objects.get(ym=_domain_name)
        _old_mess = {'registar': _old.tgs.jxs,
                     'resolver': _old.jxs.jxs,
                     'is_beian': int(_old.sfba.bh),
                     'project': _old.xm.bh,
                     'domain_env': _old.hj.hj,
                     'business': _old.ssyw.ssyw,
                     'business_type': _old.ywlx.ywlx,
                     'domain_status': int(_old.ymzt.bh),
                     'remarks': _old.bz}

        if not Acl(_domain_name, _current_user).xgdomain():
            return JsonResponse({"msg": "更新失败 权限拒绝！", "code": 5001}, safe=False)
        try:
            changedoamin = yuming.objects.get(ym=_domain_name)
            changedoamin.tgs = jxs.objects.get(jxs=_registar)
            changedoamin.jxs = jxs.objects.get(jxs=_resolver)
            changedoamin.sfba = beian.objects.get(bh=_is_beian)
            changedoamin.xm = xiangmu.objects.get(bh=_project)
            changedoamin.hj = huanjing.objects.get(hj=_domain_env)
            changedoamin.ssyw = suoshuyewu.objects.get(ssyw=_business)
            changedoamin.ywlx = ywlx.objects.get(ywlx=_business_type)
            changedoamin.ymzt = yumingzhuangtai.objects.get(bh=_domain_status)
            changedoamin.bz = _remarks
            changedoamin.save()

            gxzd = {}
            for i in _new_mess:
                if _new_mess.get(i) != _old_mess.get(i):
                    gxzd[i] = _new_mess.get(i)
            if not gxzd:
                return JsonResponse({'msg': '没有更新信息', 'code': 5001}, safe=False)
            uhistory.objects.create(ym=mess['domain_name'], user=mess['current_user'], utime=int(time.time()),
                                    uexec=f"更新域名信息:  {str(gxzd)}")
            return JsonResponse({'msg': '更新成功', 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namebasic_infodelete(request):
    if request.session.get("login", None):
        mess = json.loads(request.body)
        _domain_name = mess.get("domain_name")
        _current_user = mess['current_user']
        if not Acl(_domain_name, _current_user).scdomain():
            return JsonResponse({"msg": "删除失败 权限拒绝！", "code": 5001}, safe=False)
        try:
            yuming.objects.get(ym=_domain_name).delete()
            uhistory.objects.create(ym=mess['domain_name'], user=mess['current_user'], utime=int(time.time()),
                                    uexec=f"删除域名 ")
            return JsonResponse({'msg': '删除成功', 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namebasic_inforead(request):
    if request.session.get("login", None):
        try:
            apollo_domains = [parse.urlparse(json.loads(requests.get(
                                  "http://prodboya.api.apollo.com/configfiles/json/boya_open_api/default/application").json()[
                                                            'game.domains'])['mainland']).netloc,
                              parse.urlparse(json.loads(requests.get(
                                  "http://prodboya.api.apollo.com/configfiles/json/boya_open_api/default/application").json()[
                                                            'game.domains'])['southeast_asia']).netloc,
                              parse.urlparse(json.loads(requests.get(
                                  "http://prodboya.api.apollo.com/configfiles/json/boya_open_api/default/application").json()[
                                                            'config.cocos.public.gateway'])['mainland']).netloc,
                              parse.urlparse(json.loads(requests.get(
                                  "http://prodboya.api.apollo.com/configfiles/json/boya_open_api/default/application").json()[
                                                            'config.cocos.public.gateway'])['southeast_asia']).netloc,
                              parse.urlparse(json.loads(requests.get(
                                  "http://proddy.api.apollo.com/configfiles/json/qp-open-api/default/application").json()[
                                                            'game.domains'])['mainland']).netloc,
                              parse.urlparse(json.loads(requests.get(
                                  "http://proddy.api.apollo.com/configfiles/json/qp-open-api/default/application").json()[
                                                            'game.domains'])['southeast_asia']).netloc,
                              parse.urlparse(json.loads(requests.get(
                                  "http://proddy.api.apollo.com/configfiles/json/qp-open-api/default/application").json()[
                                                            'config.cocos.public.gateway'])['mainland']).netloc,
                              parse.urlparse(json.loads(requests.get(
                                  "http://proddy.api.apollo.com/configfiles/json/qp-open-api/default/application").json()[
                                                            'config.cocos.public.gateway'])['southeast_asia']).netloc,
                              parse.urlparse(json.loads(requests.get(
                                  "http://prodqp.api.apollo.com/configfiles/json/qp-open-api/default/application").json()[
                                                            'game.domains'])['mainland']).netloc,
                              parse.urlparse(json.loads(requests.get(
                                  "http://prodqp.api.apollo.com/configfiles/json/qp-open-api/default/application").json()[
                                                            'game.domains'])['southeast_asia']).netloc,
                              parse.urlparse(json.loads(requests.get(
                                  "http://prodqp.api.apollo.com/configfiles/json/qp-open-api/default/application").json()[
                                                            'config.cocos.public.gateway'])['mainland']).netloc,
                              parse.urlparse(json.loads(requests.get(
                                  "http://prodqp.api.apollo.com/configfiles/json/qp-open-api/default/application").json()[
                                                            'config.cocos.public.gateway'])['southeast_asia']).netloc, ]
            for i in json.loads(requests.get(
                    "http://prodqp.api.apollo.com/configfiles/json/qp-open-api/default/application").json()[
                                    'config.member.ip.domains']):
                apollo_domains.append(parse.urlparse(i['domain']).netloc)
            for i in json.loads(requests.get(
                    "http://prodqp.api.apollo.com/configfiles/json/qp-open-api/default/application").json()[
                                    'config.member.ip.gateway']):
                apollo_domains.append(parse.urlparse(i['domain']).netloc)
            for i in json.loads(requests.get(
                    "http://proddy.api.apollo.com/configfiles/json/qp-open-api/default/application").json()[
                                    'config.member.ip.domains']):
                apollo_domains.append(parse.urlparse(i['domain']).netloc)
            for i in json.loads(requests.get(
                    "http://proddy.api.apollo.com/configfiles/json/qp-open-api/default/application").json()[
                                    'config.member.ip.gateway']):
                apollo_domains.append(parse.urlparse(i['domain']).netloc)
            for i in json.loads(requests.get(
                    "http://prodboya.api.apollo.com/configfiles/json/boya_open_api/default/application").json()[
                                    'config.member.ip.domains']):
                apollo_domains.append(parse.urlparse(i['domain']).netloc)
            for i in json.loads(requests.get(
                    "http://prodboya.api.apollo.com/configfiles/json/boya_open_api/default/application").json()[
                                    'config.member.ip.gateway']):
                apollo_domains.append(parse.urlparse(i['domain']).netloc)
            _apollo_domains = list(set(apollo_domains))
        except Exception as err:
            _apollo_domains = []
            logging.debug(str(err))
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        try:
            mess = json.loads(request.body)
            _domain_name = mess.get("domain_name")
            _is_beian = mess.get("is_beian")
            _project = mess.get("project")
            _domain_env = mess.get("domain_env")
            _business = mess.get("business")
            _domain_status = mess.get("domain_status")
            allexec = yuming.objects.select_related('xm', 'sfba', 'tgs', 'jxs', 'hj', 'ssyw', 'ywlx', 'ymzt').filter(
                ym__contains=_domain_name if _domain_name else '',
                hj__in=[i.id for i in username.objects.get(username=request.session.get('user', '')).hj.all()]
                if _domain_env is None
                else [huanjing.objects.get(hj=_domain_env).id]
                if huanjing.objects.get(hj=_domain_env).id in
                   [i.id for i in username.objects.get(username=request.session.get('user', '')).hj.all()]
                else [],
                sfba__in=[i.id for i in beian.objects.filter()] if _is_beian is None else [2] if _is_beian == 1 else [
                    1],
                xm__in=[i.id for i in xiangmu.objects.filter()] if _project is None else [
                    xiangmu.objects.get(bh=_project).id],
                ssyw__in=[i.id for i in suoshuyewu.objects.filter()] if _business is None else [
                    suoshuyewu.objects.get(ssyw=_business).id],
                ymzt__in=[i.id for i in yumingzhuangtai.objects.filter()] if _domain_status is None else [
                    yumingzhuangtai.objects.get(bh=_domain_status).id])
            message = []
            for i in allexec:
                apollo_ = False
                if i.ym in _apollo_domains:
                    apollo_ = True
                message.append(
                    {"domain_name": i.ym,
                     "registar": i.tgs.jxs,
                     "resolver": i.jxs.jxs,
                     "is_beian": int(i.sfba.bh),
                     "project": i.xm.bh,
                     "domain_env": i.hj.hj,
                     "business": i.ssyw.ssyw,
                     "business_type": i.ywlx.ywlx,
                     "domain_status": int(i.ymzt.bh),
                     "remarks": i.bz,
                     "apollo": apollo_})
            if message:
                return JsonResponse({'msg': message, 'code': 200}, safe=False)
            else:
                return JsonResponse({"msg": "查无数据", "code": 5001}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def login(request):
    if request.method == "POST":  # 请求方法为POST时，进行处理
        mess = json.loads(request.body)
        _user = mess.get('username')
        _passwd = mess.get('password')
        _otp = mess.get('otp')
        try:
            if not username.objects.get(username=_user).verify_token(_otp):
                return JsonResponse({'msg': '二次认证错误', 'code': 5001}, safe=False)
            hashwd = username.objects.get(username=_user).password
            if HashDate().hashpd(_passwd, hashwd):
                request.session['user'] = _user
                request.session['login'] = True
                request.session.set_expiry(3600 * 6)
                return JsonResponse({'msg': '登陆成功', 'token': get_code(28), 'code': 200}, safe=False)
            else:
                raise ValueError("密码错误")
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': f'登陆失败{str(err)}', 'code': 5001}, safe=False)
    else:
        return JsonResponse({'msg': '403 请求错误', 'code': 5001}, safe=False)


def logout(request):
    cache._cache.clear()
    request.session.flush()
    return JsonResponse({'msg': '退出登录', 'code': 200}, safe=False)


def user_managementupdatepassword(request):
    if request.session.get("login", None):
        try:
            mess = json.loads(request.body)
            _user = mess['username']
            _passwd = mess['password']
            us = username.objects.get(username=_user)
            us.password = _passwd
            us.save()
            return JsonResponse({'msg': '更新成功', 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': f'{str(err)}', 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namessl_certread(request):
    if request.session.get("login", None):
        try:
            mess = json.loads(request.body)
            _certificate_name = mess.get("certificate_name", '')
            _domain_name = mess.get("domain_name", '')
            message = []
            for i in acmessl.objects.filter(zsmc__contains=_certificate_name, zsbdym__contains=_domain_name):
                message.append(
                    {
                        "certificate_name": i.zsmc,
                        "common_name": i.zsgym,
                        "bind_domain": i.zsbdym,
                        "total_domain_number": i.ymgs,
                        "description": i.ms,
                        "organization_name": i.bfjg,
                        "start_time": i.bfsj,
                        "end_time": i.dqsj,
                        "is_expired": crypto.load_certificate(crypto.FILETYPE_PEM, i.cer).has_expired(),
                        "iseditor": False
                    }
                )
            return JsonResponse({'msg': message, 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({'msg': str(err), 'code': 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namessl_certpublic_key_read(request):
    if request.session.get("login", None):
        mess = json.loads(request.body)
        _certificate_name = mess.get("certificate_name")
        message = acmessl.objects.get(zsmc=_certificate_name).cer
        return JsonResponse({'msg': message, 'code': 200}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namessl_certprivate_key_read(request):
    if request.session.get("login", None):
        mess = json.loads(request.body)
        _certificate_name = mess.get("certificate_name")
        message = acmessl.objects.get(zsmc=_certificate_name).key
        return JsonResponse({'msg': message, 'code': 200}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namessl_certdelete(request):
    if request.session.get("login", None):
        try:
            mess = json.loads(request.body)
            _certificate_name = mess.get("certificate_name")
            _current_user = mess.get("current_user")
            if not Acl(_certificate_name, _current_user).delssl():
                return JsonResponse({"msg": "删除SSL证书 权限拒绝！", "code": 5001}, safe=False)
            all_domain = acmessl.objects.get(zsmc=_certificate_name).zsbdym
            _dqsj = acmessl.objects.get(zsmc=_certificate_name).dqsj
            acmessl.objects.get(zsmc=_certificate_name).delete()
            uhistory.objects.create(ym=_certificate_name, user=request.session.get('user', ''), utime=int(time.time()),
                                    uexec=f"删除证书 绑定域名:{all_domain} 到期时间: {_dqsj}")
            return JsonResponse({'msg': "删除成功", 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namessl_certupdate_description(request):
    if request.session.get("login", None):
        try:
            mess = json.loads(request.body)
            _certificate_name = mess.get("certificate_name")
            _description = mess.get("description")
            acme = acmessl.objects.get(zsmc=_certificate_name)
            acme.ms = _description
            acme.save()
            uhistory.objects.create(ym=_certificate_name, user=request.session.get('user', ''), utime=int(time.time()),
                                    uexec=f"证书备注更新: {_description}")
            return JsonResponse({'msg': "更新成功", 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def domain_namessl_certupload(request):
    if request.session.get("login", None):
        try:
            mess = json.loads(request.body)
            public_key = mess.get("public_key")
            private_key = mess.get("private_key")
            _description = mess.get("description")
            acmestatus = crypto.load_certificate(crypto.FILETYPE_PEM, public_key)
            _zsgym = acmestatus.get_subject().CN
            _zsbdym = json.dumps(acmestatus.to_cryptography().extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
            _ymgs = len(acmestatus.to_cryptography().extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
            _bfjg = acmestatus.get_issuer().CN
            _bfsj = time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.strptime(f'{acmestatus.get_notBefore().decode()}'[0:13], "%Y%m%d%H%M%S"))
            _dqsj = time.strftime("%Y-%m-%d %H:%M:%S",
                                  time.strptime(f'{acmestatus.get_notAfter().decode()}'[0:13], "%Y%m%d%H%M%S"))

            new_zsgym = _zsgym
            n = 1
            while True:
                if acmessl.objects.filter(zsmc=new_zsgym):
                    new_zsgym = _zsgym + f' ({str(n)})'
                    n += 1
                else:
                    break
            acmessl.objects.create(
                zsmc=new_zsgym, zsgym=_zsgym, zsbdym=_zsbdym, ymgs=_ymgs, bfjg=_bfjg, bfsj=_bfsj, dqsj=_dqsj,
                cer=public_key,
                key=private_key, ms=_description
            )

            uhistory.objects.create(ym=_zsgym, user=request.session.get('user', ''), utime=int(time.time()),
                                    uexec=f"新增证书: {_description}")
            return JsonResponse({'msg': "新增成功", 'code': 200}, safe=False)
        except Exception as err:
            traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
            return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)


def get_code(xx):
    a = '1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    b = ''
    for i in range(xx):
        c = random.randint(0, 61)
        b += a[c]
    return b
def uploadswitch(request):
    try:
        if request.method == "POST" and request.session.get("login", None):
            _switch = upload_switch.objects.last().switch
            if _switch:
                switch = False
            else:
                switch = True
            return JsonResponse({"msg": switch, "code": 200}, safe=False)
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
##上传文件
def upload_file(request):
    backup_dirpath = "/data/django-opsweb/software/"
    try:
        if not upload_switch.objects.last().switch:
            return JsonResponse({"msg": "上传功能关闭", "code": 5001}, safe=False)
        if request.method == "POST" and request.session.get("login", None):
            file = request.FILES.get("file", None)
            if not file.name:
                return JsonResponse({"msg": "未识别的文件", "code": 5001}, safe=False)
            _file = os.path.join(backup_dirpath, file.name)
            with open(_file, 'wb+') as destination:
                for chunk in file.chunks():
                    destination.write(chunk)
            return JsonResponse({"msg": f"{file.name} 上传完成", "code": 200})
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({"msg": str(err), "code": 5001}, safe=False)

##删除文件
def delete_file(request):
    backup_dirpath = "/data/django-opsweb/software/"
    try:
        if request.method == "POST" and request.session.get("login", None):
            if not Acl(None, request.session.get('user', '')).icp_domain():
                return JsonResponse({"msg": "删除失败 权限拒绝！", "code": 5001}, safe=False)
            mess = json.loads(request.body)
            file_name= mess.get("file_name")
            _file = os.path.join(backup_dirpath, file_name)
            os.remove(_file)
            return JsonResponse({"msg": f"{file_name} 已删除 ", "code": 200}, safe=False)
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({"msg": str(err), "code": 5001}, safe=False)

##文件列表
def software_list(request):
    try:
        if request.session.get("login", None) and request.session.get("login", None):
            files_path = "/data/django-opsweb/software"
            files = os.listdir(files_path)
            data = []
            for i in files:
                file = os.path.join(files_path, i)
                file_size = str(round(os.path.getsize(file) / (1024 * 1024), 4)) + 'MB'
                file_ctime = time.strftime("%F %T", time.localtime(os.path.getctime(file)))
                data.append({"file": file, "file_name": i, "file_size": file_size, "file_ctime": file_ctime})
            return JsonResponse({"msg": data, "code": 200}, safe=False)
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({"msg": str(err), "code": 5001}, safe=False)

##下载文件
def software(request):
    try:
        filename = request.GET["s"]
        backup_dirpath = '/data/django-opsweb/software/'
        down_file = open(os.path.join(backup_dirpath, filename), 'rb')
        response = FileResponse(down_file, filename=filename, as_attachment=True)
        response['Content-Type'] = 'application/octet-stream'
        return response
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({"msg": str(err), "code": 5001}, safe=False)

##下载备份
def download_file(request):
    try:
        backup_dirpath = "/data/django-opsweb/backup/"
        if request.session.get("login", None):
            pass
        elif request.method == "POST":
            mess = json.loads(request.body)
            _user = mess.get('user', None)
            _passwd = mess.get('token', None)
            hashwd = username.objects.get(username=_user).password
            if not HashDate().hashpd(_passwd, hashwd) or _passwd is None:
                return HttpResponse(" token 不正确！！")
        else:
            return HttpResponse('{"msg": "403 非法请求 或 SESSION过期", "code": 5001}')

        # docker备份 opsweb 数据库
        backupfile = time.strftime("%F_%Hh_%Mm", time.localtime(time.time())) + '_opsweb.sql'
        os.system(
            f'docker exec  mysql8.0  bash -c "mysqldump  -uroot -prhqUz1JO8mfA6TV0QhRyOzTcX523HB --databases opsweb"  >  {os.path.join(backup_dirpath, backupfile)}')

        # 打包成tar格式
        taring = tarfile.open(
            os.path.join(backup_dirpath, "django-opsweb_" + time.strftime("%F_%Hh_%Mm", time.localtime(
                time.time())) + ".tar.gz"), "w:gz")
        os.chdir(backup_dirpath)
        taring.add(backupfile)
        taring.close()
        os.remove(os.path.join(backup_dirpath, backupfile))

        # 本地只保留上传的100个备份文件
        allbackup = sorted(os.listdir(backup_dirpath), key=lambda x: os.path.getmtime(os.path.join(backup_dirpath, x)))
        for i in range(len(os.listdir(backup_dirpath)) - 100):
            os.remove(os.path.join(backup_dirpath, allbackup[i]))

        # 返回最新opsweb备份文件
        backup_filename = \
            sorted(os.listdir(backup_dirpath), key=lambda x: os.path.getmtime(os.path.join(backup_dirpath, x)))[-1]
        down_file = open(os.path.join(backup_dirpath, backup_filename), 'rb')
        response = FileResponse(down_file, filename=backup_filename, as_attachment=True)
        response['Content-Type'] = 'application/octet-stream'
        return response
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({"msg": str(err), "code": 5001}, safe=False)


def getDomainStatus(request):
    try:
        if request.method == "POST":
            jsdata = []
            mess = json.loads(request.body)
            opskey = mess.get('opskey')
            pan = mess.get('pan')
            domain_name = mess.get('domain_name')
            hashwd = username.objects.get(username='api').password
            if not HashDate().hashpd(opskey, hashwd) or opskey is None:
                return JsonResponse("opskey 无效！", status=403, safe=False)
            if pan == 'all':
                _all_domain = yuming.objects.select_related("xm", "ymzt", "jxs", "hj").prefetch_related(
                    Prefetch('cdn', queryset=cdn.objects.filter().select_related('jxs'))).filter(
                    ym__contains=domain_name)
                for _domain in _all_domain:
                    _allcdn = []
                    for i in _domain.cdn.all():
                        _allcdn.append({"cdn": i.jxs.jxs, "vaule": i.jxz})
                    jsdata.append(
                        {'domain': _domain.ym, 'domain_status': int(_domain.ymzt.bh), 'project': _domain.xm.bh,
                         'env': _domain.hj.hj, 'remarks': _domain.bz, "cdn": _allcdn})

            else:
                _all_domain = yuming.objects.filter(ym=domain_name)
                for _domain in _all_domain:
                    jsdata.append({'domain': _domain.ym, 'domain_status': int(_domain.ymzt.bh), 'remarks': _domain.bz})
                    break
            return JsonResponse(jsdata, safe=False)
        else:
            return JsonResponse("请求方式错误！", status=403, safe=False)
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({"msg": str(err), "code": 5001}, safe=False)


def getUsingDomainInfoByEnv(request):
    try:
        if request.method == "POST":
            jsdata = []
            mess = json.loads(request.body)
            opskey = mess.get('opskey')
            _domain_env = mess.get('domain_env')
            hashwd = username.objects.get(username='api').password
            if not HashDate().hashpd(opskey, hashwd) or opskey is None:
                return JsonResponse("opskey 无效！", status=403, safe=False)
            _hj = huanjing.objects.get(hj=_domain_env).id
            for _domain in yuming.objects.select_related('xm', 'ssyw').filter(ymzt=2, hj=_hj):
                jsdata.append({"domain_name": _domain.ym, "project": _domain.xm.bh, "business": _domain.ssyw.ssyw,
                               "remarks": _domain.bz})
            return JsonResponse(jsdata, safe=False)
        else:
            return JsonResponse("请求方式错误！", status=403, safe=False)
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({"msg": str(err), "code": 5001}, safe=False)


def get_certain_cloud_vendor_domain_info(request):
    try:
        if request.method == "POST":
            jsdata = []
            mess = json.loads(request.body)
            opskey = mess.get('opskey')
            _domain_env = mess.get('domain_env')
            _type = mess.get('type')
            cloud_vendor_name = mess.get('cloud_vendor_name')
            hashwd = username.objects.get(username='api').password
            if not HashDate().hashpd(opskey, hashwd) or opskey is None:
                return JsonResponse("opskey 无效！", status=403, safe=False)
            _hj = huanjing.objects.get(hj='prod').id
            for _domain in yuming.objects.select_related('xm', 'ssyw', 'hj', 'ymzt').prefetch_related(
                    Prefetch('cdn', queryset=cdn.objects.filter().select_related('jxs'))).filter(
                hj__in=[i.id for i in huanjing.objects.filter()] if _domain_env == 'all' else [_hj]):
                for _domain_cdn in _domain.cdn.all():
                    if _type == 'all':
                        if _domain_cdn.jxs.jxs == cloud_vendor_name:
                            jsdata.append(
                                {"domain_name": _domain.ym, "project": _domain.xm.bh, "domain_env": _domain.hj.hj,
                                 "business": _domain.ssyw.ssyw, "domain_status": int(_domain.ymzt.bh)})
                    else:
                        if _domain_cdn.jxs.jxs == cloud_vendor_name and _domain_cdn.jxlx == "CNAME":
                            jsdata.append(
                                {"domain_name": _domain.ym, "project": _domain.xm.bh, "domain_env": _domain.hj.hj,
                                 "business": _domain.ssyw.ssyw, "domain_status": int(_domain.ymzt.bh)})

            return JsonResponse(jsdata, safe=False)
        else:
            return JsonResponse("请求方式错误！", status=403, safe=False)
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({"msg": str(err), "code": 5001}, safe=False)


def update_cloud_key(request):
    try:
        if request.method == "POST":
            mess = json.loads(request.body)
            _token = mess.get("token")
            hashwd = username.objects.get(username='cloud').password
            if not HashDate().hashpd(_token, hashwd) or _token is None:
                return JsonResponse({"msg": "token 认证失败", "code": 5001}, safe=False)
        elif request.session.get("login", None):
            if not Acl(None, request.session.get('user', '')).update_cloud_key():
                return JsonResponse({"msg": "更新失败 权限拒绝！", "code": 5001}, safe=False)
        else:
            return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)

        data = {}
        for i in jxs.objects.filter():
            _cloud_data = {}
            if i.cs == 'ali':
                _jxs = jxs.objects.get(jxs=i.jxs)
                old_gy = _jxs.get_gy()
                old_sy = _jxs.get_sy()
                ali = aliapi.Alikey(old_gy, old_sy)
                try:
                    _cloud_key_now = ali.select_AccessKey()
                    _cloud_data['get_cloud_key'] = True
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                    _cloud_data['Successful'] = 'get_cloud_key_err ' + str(err)
                    data[i.jxs] = _cloud_data
                    continue
                if len(json.loads(_cloud_key_now)['AccessKeys']['AccessKey']) == 2:
                    _cloud_data['len_key_before'] = 2
                    for _key in json.loads(_cloud_key_now)['AccessKeys']['AccessKey']:
                        if _key.get("AccessKeyId") != old_gy:
                            try:
                                ali.delete_AccessKey(_key.get("AccessKeyId"))
                                _cloud_data['delete_other_key'] = True
                            except Exception as err:
                                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                                _cloud_data['Successful'] = 'delete_other_key_err ' + str(err)
                                data[i.jxs] = _cloud_data
                                continue
                try:
                    new_key = ali.create_AccessKey()
                    new_key_id = json.loads(new_key)['AccessKey']['AccessKeyId']
                    new_key_secret = json.loads(new_key)['AccessKey']['AccessKeySecret']
                    _cloud_data['get_new_key'] = new_key_id
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                    _cloud_data['Successful'] = 'get_new_key_err ' + str(err)
                    data[i.jxs] = _cloud_data
                    continue
                try:
                    _jxs.gy = new_key_id
                    _jxs.sy = new_key_secret
                    if _jxs.acme:
                        _jxs.acme = _jxs.get_acme().replace(old_gy, new_key_id).replace(old_sy, new_key_secret)
                        _cloud_data['update_acme_new_key'] = True
                    _jxs.save()
                    _cloud_data['update_dns_new_key'] = True
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                    _cloud_data['Successful'] = 'update_new_key_err ' + str(err)
                    data[i.jxs] = _cloud_data
                    continue
                try:
                    ali.delete_AccessKey(old_gy)
                    _cloud_data['delete_old_key'] = old_gy
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                    _cloud_data['Successful'] = 'delete_old_key_err ' + str(err)
                    data[i.jxs] = _cloud_data
                    continue
                _cloud_data['Successful'] = True
                data[i.jxs] = _cloud_data
            elif i.cs == 'huawei':
                _jxs = jxs.objects.get(jxs=i.jxs)
                old_gy = _jxs.get_gy()
                old_sy = _jxs.get_sy()
                zh_id = jxs.objects.get(jxs=i.jxs).zh_id
                admin_zh_id = jxs.objects.get(jxs=i.jxs).admin_zh_id
                huawei = huaweiapi.Hwkey(old_gy, old_sy, admin_zh_id)
                try:
                    _cloud_key_now = huawei.select_AccessKey(zh_id)
                    _cloud_data['get_cloud_key'] = True
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                    _cloud_data['Successful'] = 'get_cloud_key_err ' + str(err)
                    data[i.jxs] = _cloud_data
                    continue
                if len(_cloud_key_now.to_dict()['credentials']) == 2:
                    _cloud_data['len_key_before'] = 2
                    for _key in _cloud_key_now.to_dict()['credentials']:
                        if _key.get("access") != old_gy:
                            try:
                                huawei.delete_AccessKey(_key.get("access"))
                                _cloud_data['delete_other_key'] = True
                            except Exception as err:
                                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                                _cloud_data['Successful'] = 'delete_other_key_err ' + str(err)
                                data[i.jxs] = _cloud_data
                                continue
                try:
                    new_key = huawei.create_AccessKey(zh_id)
                    new_key_id = new_key.to_dict()['credential']['access']
                    new_key_secret = new_key.to_dict()['credential']['secret']
                    _cloud_data['get_new_key'] = new_key_id
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                    _cloud_data['Successful'] = 'get_new_key_err ' + str(err)
                    data[i.jxs] = _cloud_data
                    continue
                try:
                    _jxs.gy = new_key_id
                    _jxs.sy = new_key_secret
                    _jxs.save()
                    _cloud_data['update_dns_new_key'] = True
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                    _cloud_data['Successful'] = 'update_new_key_err ' + str(err)
                    data[i.jxs] = _cloud_data
                    continue
                try:
                    huawei.delete_AccessKey(old_gy)
                    _cloud_data['delete_old_key'] = old_gy
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                    _cloud_data['Successful'] = 'delete_old_key_err ' + str(err)
                    data[i.jxs] = _cloud_data
                    continue
                _cloud_data['Successful'] = True
                data[i.jxs] = _cloud_data

            elif i.cs == 'aws':
                _jxs = jxs.objects.get(jxs=i.jxs)
                old_gy = _jxs.get_gy()
                old_sy = _jxs.get_sy()
                aws = awsapi.AWSIAMApi(old_gy, old_sy)
                try:
                    _cloud_key_now = aws.list_user_access_key()
                    _cloud_data['get_cloud_key'] = True
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                    _cloud_data['Successful'] = 'get_cloud_key_err ' + str(err)
                    data[i.jxs] = _cloud_data
                    continue
                if len(_cloud_key_now) == 2:
                    _cloud_data['len_key_before'] = 2
                    for _key in _cloud_key_now:
                        if _key.get("AccessKeyId") != old_gy:
                            try:
                                aws.delete_user_access_key(_access_key_id=_key.get("AccessKeyId"))
                                _cloud_data['delete_other_key'] = True
                            except Exception as err:
                                traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                                _cloud_data['Successful'] = 'delete_other_key_err ' + str(err)
                                data[i.jxs] = _cloud_data
                                continue
                try:
                    new_key = aws.create_user_access_key()
                    new_key_id = new_key['AccessKeyId']
                    new_key_secret = new_key['SecretAccessKey']
                    _cloud_data['get_new_key'] = new_key_id
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                    _cloud_data['Successful'] = 'get_new_key_err ' + str(err)
                    data[i.jxs] = _cloud_data
                    continue
                try:
                    _jxs.gy = new_key_id
                    _jxs.sy = new_key_secret
                    _jxs.save()
                    _cloud_data['update_dns_new_key'] = True
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                    _cloud_data['Successful'] = 'update_new_key_err ' + str(err)
                    data[i.jxs] = _cloud_data
                    continue
                try:
                    aws.delete_user_access_key(_access_key_id=old_gy)
                    _cloud_data['delete_old_key'] = old_gy
                except Exception as err:
                    traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
                    _cloud_data['Successful'] = 'delete_old_key_err ' + str(err)
                    data[i.jxs] = _cloud_data
                    continue
                _cloud_data['Successful'] = True
                data[i.jxs] = _cloud_data
            else:
                data[i.jxs] = {'Successful': "cloud_not_config"}
        logging.debug(data)
        for _cloud in data:
            if data.get(_cloud)['Successful'] != 'cloud_not_config':
                uhistory.objects.create(ym=f"更新云厂商密钥 {_cloud}", user=request.session.get('user', ''),
                                        utime=int(time.time()),
                                        uexec=data.get(_cloud)['Successful'])
        return JsonResponse(data, safe=False)
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({"msg": str(err), "code": 5001}, safe=False)


def select_cloud_key(request):
    try:
        if request.method == "POST":
            mess = json.loads(request.body)
            _token = mess.get("token")
            hashwd = username.objects.get(username='cloud').password
            if not HashDate().hashpd(_token, hashwd) or _token is None:
                return JsonResponse({"msg": "token 认证失败", "code": 5001}, safe=False)
        elif request.session.get("login", None):
            if not Acl(None, request.session.get('user', '')).select_cloud_key():
                return JsonResponse({"msg": "查询失败 权限拒绝！", "code": 5001}, safe=False)
        else:
            return JsonResponse({"msg": "403 非法请求 或 SESSION过期", "code": 5001}, safe=False)

        data = []
        for i in jxs.objects.filter():
            _cloud = {}
            _cloud['account_name'] = i.jxs
            _cloud['account_cloud'] = i.cs
            _cloud['admin_account'] = i.admin_zh
            _cloud['admin_account_id'] = i.admin_zh_id
            _cloud['iam_account'] = i.zh
            _cloud['iam_account_id'] = i.zh_id
            _cloud['iam_public_key'] = i.get_gy()
            _cloud['iam_private_key'] = i.get_sy()
            if i.acme:
                _cloud['acme_export'] = i.get_acme()
            data.append(_cloud)
        return JsonResponse({"msg": data, "code": 200}, safe=False)

    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({"msg": str(err), "code": 5001}, safe=False)


def update_aliyun_cdn_iplist(request):
    """
    :param _project:                所属项目   （必填)
    :param _backadmin_add_ips:      本次backadmin新增IP
    :param _backadmin_del_ips:      本次backadmin删除IP
    :param _api_add_ips:            本次API新增IP
    :param _api_del_ips:            本次API删除IP
    :param _new_ip_data:            最新IP列表数据，阿里云CDN白名单是全量更新，所以需要这个数据 （必填)
    :param _force:                  是否忽略变更数据(没有变更也执行同步)
    :param _cdn_sync_failed_data    上次失败任务   （必填)
    ### 弃用项目
    try:
        if request.method == "POST":
            mess = json.loads(request.body)
            _token = mess.get("token")
            hashwd = username.objects.get(username='ipwhite').password
            if not HashDate().hashpd(_token, hashwd) or _token is None:
                return JsonResponse({"msg": "token 认证失败", "code": 5001}, safe=False)
        else:
            return JsonResponse({"msg": "403 非法请求", "code": 5001}, safe=False)
        _force = False
        _project = mess.get('_project')
        _backadmin_add_ips = mess.get('_backadmin_add_ips')
        _backadmin_del_ips = mess.get('_backadmin_del_ips')
        _api_add_ips = mess.get('_api_add_ips')
        _api_del_ips = mess.get('_api_del_ips')
        _new_ip_data = mess.get('_new_ip_data')
        _force = mess.get('_force')
        CDN_SYNC_FAILED_DATA = mess.get('_cdn_sync_failed_data')
        if None in [_project, _new_ip_data, CDN_SYNC_FAILED_DATA]:
            raise Exception("缺少必要参数")
        cdn_tag_list = ['aliyun-inter', 'aliyun-inter2']
        domain_data = {}
        msg = {}
        logs = []
        notify = []
        for cdn_tag in cdn_tag_list:
            csy = jxs.objects.get(jxs=cdn_tag).get_sy()
            cgy = jxs.objects.get(jxs=cdn_tag).get_gy()
            aliyun_dcdn_api = aliapi.AliDCDNApi(cgy, csy)
            #白名单只对配置在DCDN域名生效
            domain_all_in_dcdn = aliapi.AliyunDcdnApi(cgy,csy).domain_all_in_dcdn()
            # 从opsweb获取CDN域名列表
            _cloud_name = cdn_tag
            domain_data.update({_cloud_name: {}})
            jsdata = []
            _hj = huanjing.objects.get(hj='prod').id
            for _domain in yuming.objects.filter(hj=_hj).select_related('xm', 'ssyw', 'hj', 'ymzt').prefetch_related(
                    Prefetch('cdn', queryset=cdn.objects.filter().select_related('jxs'))):
                for _domain_cdn in _domain.cdn.all():
                    if _domain_cdn.jxs.jxs == cdn_tag and _domain_cdn.jxlx == "CNAME":
                        jsdata.append(
                            {"domain_name": _domain.ym, "project": _domain.xm.bh, "domain_env": _domain.hj.hj,
                             "business": _domain.ssyw.ssyw, "domain_status": int(_domain.ymzt.bh)})
            for di in jsdata:
                d_name = di.get('domain_name')
                d_project = di.get('project')
                d_business = di.get('business')
                if d_project not in domain_data[_cloud_name]:
                    domain_data[_cloud_name][d_project] = {}
                if d_business not in domain_data[_cloud_name][d_project]:
                    domain_data[_cloud_name][d_project][d_business] = []
                domain_data[_cloud_name][d_project][d_business].append(d_name)
            _domain_data = domain_data.get(_cloud_name)
            _last_failed_data = CDN_SYNC_FAILED_DATA[_project][cdn_tag]
            if _domain_data:
                # 阿里云CDN加白域名与IP列表信息
                # 管理后台域名：需要给项目下所有 backadmin,console 域名增加
                _backadmin_domains = _domain_data.get(_project.lower(),{}).get('backadmin',[])
                _console_domains = _domain_data.get(_project.lower(),{}).get('console-setting',[])
                aliyun_backadmin_domains = _backadmin_domains + _console_domains
                aliyun_backadmin_domains = list(set(aliyun_backadmin_domains).intersection(set(domain_all_in_dcdn)))
                # API域名：需要给项目下所有 betinfo,openapi 域名增加
                _betinfo_domains = _domain_data.get(_project.lower(),{}).get('betinfo',[])
                _openapi_domains = _domain_data.get(_project.lower(),{}).get('openapi',[])
                aliyun_api_domains = _betinfo_domains + _openapi_domains
                aliyun_api_domains = list(set(aliyun_api_domains).intersection(set(domain_all_in_dcdn)))
                # 管理后台IP：backadmin IP列表
                aliyun_backadmin_ips = _new_ip_data[f'{_project}-BACKADMIN']
                # API IP： api-group + api-common
                aliyun_api_ips = _new_ip_data[f'{_project}-API-GROUP'] + _new_ip_data[f'{_project}-API-COMMON']

                if aliyun_backadmin_domains:


                    # 更新指定项目管理后台白名单-新增/删除 阿里云白名单是全量更新，所以新增跟删除只需要执行一次
                    # 执行条件：有新增或删除IP 或 有上次未更新成功记录 或 手动执行强制同步
                    if _backadmin_add_ips or _backadmin_del_ips or _last_failed_data.get('backadmin') or (
                            _force and _backadmin_add_ips is not None):
                        if _last_failed_data.get('backadmin'):
                            logs.append({"info": f'重试更新 -> 上次未成功更新的IP白名单列表：{_project}:backadmin'})
                        logs.append({"info":
                                         f'>>> {cdn_tag} 更新阿里云CDN域名白名单: 白名单列表: {_project}-backadmin[{len(aliyun_backadmin_ips)}] 更新域名: {aliyun_backadmin_domains}'})
                        ali_ret = aliyun_dcdn_api.set_domain_ip_allow_list(aliyun_backadmin_domains,
                                                                           aliyun_backadmin_ips)
                        if ali_ret['success']:
                            # apploger.info(ali_ret)
                            logs.append({"info": '更新成功'})
                            # 成功，清空失败列表
                            CDN_SYNC_FAILED_DATA[_project][cdn_tag]['backadmin'] = False
                        else:
                            # 失败，将本次IP加入失败列表
                            err_msg = f'# {_project.upper()}:BACKADMIN \n> {cdn_tag.upper()} CDN 更新失败,将再下次重试更新'
                            logs.append({"warning": err_msg + f'\nInfo: {ali_ret}'})
                            notify.append(['error', 5, err_msg])
                            CDN_SYNC_FAILED_DATA[_project][cdn_tag]['backadmin'] = True
                    else:
                        logs.append({"info": f'{cdn_tag}帐号 {_project} 项目backadmin 无更新'})
                else:
                    logs.append({"info": f'{cdn_tag}帐号上没有{_project}项目backadmin域名.skip..'})

                if aliyun_api_domains:

                    # 更新指定项目API白名单-新增/删除
                    if _api_add_ips or _api_del_ips or _last_failed_data.get('api') or (
                            _force and _api_add_ips is not None):
                        if _last_failed_data.get('api'):
                            logs.append({"info": f'重试更新 -> 上次未成功更新的IP白名单列表：{_project}:api'})
                        logs.append({"info":
                                         f'>>> {cdn_tag} 更新阿里云CDN域名白名单:  白名单列表: {_project}-api:[{len(aliyun_api_ips)}] 更新域名: {aliyun_api_domains}'})
                        ali_ret = aliyun_dcdn_api.set_domain_ip_allow_list(aliyun_api_domains, aliyun_api_ips)
                        if ali_ret['success']:
                            # apploger.info(ali_ret)
                            logs.append({"info": '更新成功'})
                            # 成功，清空失败列表
                            CDN_SYNC_FAILED_DATA[_project][cdn_tag]['api'] = False
                        else:
                            # 失败，将本次IP加入失败列表
                            err_msg = f'# {_project.upper()}:API \n> {cdn_tag.upper()} CDN 更新失败,将再下次重试更新'
                            logs.append({"warning": err_msg + f'\nInfo: {ali_ret}'})
                            notify.append(['error', 5, err_msg])
                            CDN_SYNC_FAILED_DATA[_project][cdn_tag]['api'] = True
                    else:
                        logs.append({"info": f'{cdn_tag}帐号 {_project} 项目api 无更新'})
                else:
                    logs.append({"info": f'{cdn_tag}帐号上没有{_project}项目api域名.skip..'})
            else:
                err_msg = f'{cdn_tag}  域名列表为空,此次未更新阿里云,加入失败列表,将在下一次重试更新'
                logs.append({"warning": err_msg})
                notify.append(['error', 5, err_msg])
                # 域名列表获取失败，那此次也没有更新，记录到失败列表
                if _backadmin_add_ips or _backadmin_del_ips:
                    CDN_SYNC_FAILED_DATA[_project][cdn_tag]['backadmin'] = True
                if _api_add_ips or _api_del_ips:
                    CDN_SYNC_FAILED_DATA[_project][cdn_tag]['api'] = True
        msg.update({"logs": logs})
        msg.update({"notify": notify})
        msg.update({"cdn_sync_failed_data": CDN_SYNC_FAILED_DATA})
        msg.update({"code": 200})
        return JsonResponse(msg, safe=False)
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    """
    return JsonResponse({"msg": "弃用项目", "code": 5001}, safe=False)

def switch_aliyun_ipwhite_valide(request):

    """
    阿里云白名单验证开关,
    - 开启:把当前版本IP列表同步到阿里云(阿里云关闭白名单验证相当于白名单清空,所以开启时要重新同步)
    - 关闭:关闭阿里云CDN白名单配置
    Args:
        project (str):          # 项目类型
        iplist_type (str):      # 白名单类型
        switch (str):           # 开或关
        ip_list_data (list)     # 最新IP列表数据，阿里云CDN白名单是全量更新，所以需要这个数据 （必填)
    ### 弃用
    try:
        if request.method == "POST":
            mess = json.loads(request.body)
            _token = mess.get("token")
            hashwd = username.objects.get(username='ipwhite').password
            if not HashDate().hashpd(_token, hashwd) or _token is None:
                return JsonResponse({"msg": "token 认证失败", "code": 5001}, safe=False)
            iplist_type = mess.get('iplist_type')
            project = mess.get('project')
            switch = mess.get('switch')
            ip_list_data = mess.get('ip_list_data')
            if None in [iplist_type, project, switch, ip_list_data]:
                raise Exception("缺少必要参数")
        else:
            return JsonResponse({"msg": "403 非法请求", "code": 5001}, safe=False)
        cdn_tag_list = ['aliyun-inter', 'aliyun-inter2']
        domain_data = {}
        msg = {}
        logs = []
        for cdn_tag in cdn_tag_list:
            csy = jxs.objects.get(jxs=cdn_tag).get_sy()
            cgy = jxs.objects.get(jxs=cdn_tag).get_gy()
            aliyun_dcdn_api = aliapi.AliDCDNApi(cgy, csy)
            # 白名单只对配置在DCDN域名生效
            domain_all_in_dcdn = aliapi.AliyunDcdnApi(cgy,csy).domain_all_in_dcdn()
            # 获取阿里云域名列表
            _cloud_name = cdn_tag
            domain_data.update({_cloud_name: {}})
            jsdata = []
            _hj = huanjing.objects.get(hj='prod').id
            for _domain in yuming.objects.filter(hj=_hj).select_related('xm', 'ssyw', 'hj', 'ymzt').prefetch_related(
                    Prefetch('cdn', queryset=cdn.objects.filter().select_related('jxs'))):
                for _domain_cdn in _domain.cdn.all():
                    if _domain_cdn.jxs.jxs == cdn_tag and _domain_cdn.jxlx == "CNAME":
                        jsdata.append(
                            {"domain_name": _domain.ym, "project": _domain.xm.bh, "domain_env": _domain.hj.hj,
                             "business": _domain.ssyw.ssyw, "domain_status": int(_domain.ymzt.bh)})
            for di in jsdata:
                d_name = di.get('domain_name')
                d_project = di.get('project')
                d_business = di.get('business')
                if d_project not in domain_data[_cloud_name]:
                    domain_data[_cloud_name][d_project] = {}
                if d_business not in domain_data[_cloud_name][d_project]:
                    domain_data[_cloud_name][d_project][d_business] = []
                domain_data[_cloud_name][d_project][d_business].append(d_name)
            _domain_data = domain_data.get(_cloud_name)
            if _domain_data:
                if iplist_type == "backadmin":
                    # 管理后台域名：需要给项目下所有 backadmin,console 域名增加
                    _backadmin_domains = _domain_data.get(project.lower()).get('backadmin')
                    _console_domains = _domain_data.get(project.lower()).get('console-setting')
                    domains = _backadmin_domains + _console_domains
                    ip_list = ip_list_data[f'{project.upper()}-BACKADMIN']
                else:
                    # API域名：需要给项目下所有 betinfo,openapi 域名增加
                    _betinfo_domains = _domain_data.get(project.lower()).get('betinfo')
                    _openapi_domains = _domain_data.get(project.lower()).get('openapi')
                    domains = _betinfo_domains + _openapi_domains
                    ip_list = ip_list_data[f'{project.upper()}-API-GROUP'] + ip_list_data[
                        f'{project.upper()}-API-COMMON']
                ip_list = list(set(ip_list).intersection(set(domain_all_in_dcdn)))
                if domains:
                    if switch == 'off':
                        logs.append(
                            {"info": f'{switch.upper()}  {cdn_tag} 阿里云IP白名单验证: {project}-{iplist_type} 域名: {domains}'})
                        ret = aliyun_dcdn_api.delete_domain_config(domains, ['ip_allow_list_set'])
                        logs.append({"info": f'{cdn_tag} 阿里云操作结果: {ret}'})
                    else:
                        logs.append({
                            "info": f'{switch.upper()}  {cdn_tag} 阿里云IP白名单验证: {project}-{iplist_type}[{len(ip_list)}] 域名: {domains}'})
                        ret = aliyun_dcdn_api.set_domain_ip_allow_list(domains, ip_list)
                        logs.append({"info": f'{cdn_tag} 阿里云操作结果: {ret}'})
                else:
                    logs.append({"info": f'{cdn_tag} 帐号上没有{project}项目{iplist_type}域名.skip..'})
            else:
                err_msg = f'{cdn_tag} {project}-{iplist_type}  域名列表为空'
                logs.append({"warning": err_msg})
        msg.update({"logs": logs})
        msg.update({"code": 200})
        return JsonResponse(msg, safe=False)
    except Exception as err:
        traceback.print_exc(file=open('/data/django-opsweb/opsweb.log', 'a'))
        return JsonResponse({"msg": str(err), "code": 5001}, safe=False)
    """
    return JsonResponse({"msg": "弃用项目", "code": 5001}, safe=False)