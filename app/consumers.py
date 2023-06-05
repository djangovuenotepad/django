from channels.generic.websocket import WebsocketConsumer
from app.models import *
from OpenSSL import crypto
from cryptography import x509
import subprocess, os, threading, time, json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'rest.settings')
os.environ["DJANGO_ALLOW_ASYNC_UNSAFE"] = "true"


class ChatConsumer(WebsocketConsumer):
    def websocket_connect(self, message):
        self.accept()
        self.send(json.dumps({'msg': "服务器已经收到你的请求"}))

    def thread(self, shell_exec, _cer_name):
        p = subprocess.Popen(shell_exec, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0,
                             universal_newlines=True, shell=True)
        while True:
            line = p.stdout.readline()
            if line:
                self.send(json.dumps({"msg": line}))
            else:
                p.poll()
                if p.returncode == 0:
                    self.send(json.dumps({'msg': '证书申请成功！'}))
                    try:
                        with open(f"/data/acme/data/{_cer_name}/{_cer_name}.key", 'r', encoding='utf-8') as f:
                            _key = f.read()
                        with open(f"/data/acme/data/{_cer_name}/fullchain.cer", 'r', encoding='utf-8') as f:
                            _cer = f.read()
                        acmestatus = crypto.load_certificate(crypto.FILETYPE_PEM,
                                                             open(f"/data/acme/data/{_cer_name}/fullchain.cer",
                                                                  'rb').read())
                        # 主题
                        _zsgym = acmestatus.get_subject().CN
                        _zsbdym = json.dumps(acmestatus.to_cryptography().extensions.get_extension_for_class(
                            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
                        _ymgs = len(acmestatus.to_cryptography().extensions.get_extension_for_class(
                            x509.SubjectAlternativeName).value.get_values_for_type(x509.DNSName))
                        _bfjg = acmestatus.get_issuer().CN
                        _bfsj = time.strftime("%Y-%m-%d %H:%M:%S",
                                              time.strptime(f'{acmestatus.get_notBefore().decode()}'[0:13],
                                                            "%Y%m%d%H%M%S"))
                        _dqsj = time.strftime("%Y-%m-%d %H:%M:%S",
                                              time.strptime(f'{acmestatus.get_notAfter().decode()}'[0:13],
                                                            "%Y%m%d%H%M%S"))

                        new_cer_name = _cer_name
                        n = 1
                        while True:
                            if acmessl.objects.filter(zsmc=new_cer_name):
                                new_cer_name = _cer_name + f' ({str(n)})'
                                n += 1
                            else:
                                break

                        acmessl.objects.create(
                            zsmc=new_cer_name, zsgym=_zsgym, zsbdym=_zsbdym, ymgs=_ymgs, bfjg=_bfjg, bfsj=_bfsj,
                            dqsj=_dqsj, cer=_cer, key=_key,
                        )
                        self.send(json.dumps({'msg': '证书 存储数据库成功！'}))
                    except Exception as err:
                        self.send(json.dumps({'msg': f'{str(err)}'}))
                else:
                    self.send(json.dumps({'msg': '证书申请失败！'}))
                break

    def websocket_receive(self, message):
        try:
            """客户端发送数据过来  自动触发"""
            mess = json.loads(message['text'])
            _allcloud = []
            _alldomain = []
            _cer_name = mess.get("certificate_name")
            export_exec = ''
            acme_exec = '/data/acme/acme.sh --issue --force --config-home "/data/acme/data" '
            for i in mess.get("domain_list"):
                resolver = i.get("resolver")
                resolver = resolver.replace('.', '_').replace('-', '_')
                acme_exec += f' --dns dns_{resolver} -d {i.get("domain_name")} '
                _allcloud.append(i.get("resolver"))
                _alldomain.append(i.get("domain_name"))
            self.send(json.dumps({"msg": f"申请的域名: {_alldomain}"}))
            self.send(json.dumps({"msg": f"需要用到的云厂商: {set(_allcloud)}"}))
            for i in set(_allcloud):
                try:
                    exports = jxs.objects.get(jxs=i).get_acme()
                    if not exports:
                        raise Exception(f"{i} 没有配置acme")
                    for export in exports.split("\r\n"):
                        export_exec += f"{export} ; "
                    self.send(json.dumps({"msg": f"已导入 {i} 环境变量"}))
                except IndexError:
                    raise Exception(f"{i} 没有配置acme")
            self.send(json.dumps({"msg": f"执行证书申请命令: {acme_exec}"}))
            shell_exec = export_exec + acme_exec
            threading.Thread(target=self.thread, args=(shell_exec, _cer_name)).start()
        except Exception as err:
            self.send(json.dumps({"msg": f"{str(err)} ！！！"}))

    def websocket_disconnect(self, message):
        print("ws 服务器端 断开连接 ！！")
