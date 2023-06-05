### 项目框架：  nginx + supervisord + gunicorn(django) + daphne(websocket) 
### PYTHON目录:  /usr/local/python3.9/bin/python3
### 项目部署目录：   /data/django-opsweb/
~~~shell
acme部署
cd /opt && git clone https://github.com/acmesh-official/acme.sh.git
cd acme.sh && ./acme.sh --install --home /data/acme --install --config-home /data/acme/data  
cd /data/acme/ && ./acme.sh --register-account  -m justdmail.@mail.com && ./acme.sh acme.sh --set-default-ca --server zerossl
cp /data/django-opsweb/acme_dnsapi/* /data/acme/dnsapi/

1.创建虚拟环境
pip3.9 install virtualenvwrapper

2. /root/.bachrc 加载 virtualenvwrapper命令（python安装目录不同 find 查找各路径)
export VIRTUALENVWRAPPER_PYTHON=/usr/local/python3.9/bin/python3.9
export VIRTUALENVWRAPPER_VIRTUALENV=/usr/local/python3.9/bin/virtualenv
source /usr/local/python3.9/bin/virtualenvwrapper.sh

3.启动django-opsweb虚拟环境
source /root/.bashrc && mkvirtualenv  django-opsweb
workon django-opsweb
4.虚拟环境下安装依赖
cd /data/django-opsweb/
pip3.9 install -r requirements.txt

5.修改数据库
cat ops/settings.py |grep -A 8 mysql
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'opsweb',
        'USER': 'root',
        'PASSWORD':******,
        'HOST':'localhost',
        'PORT':'3306',
        
6.django模型同步到数据库
python3.9  manage.py makemigrations
python3.9  manage.py migrate

7.创建后台登录超级管理员
python3.9  manage.py createsuperuser
~~~
### gunicorn+daphne 启动项目,静态文件交给nginx处理
~~~txt
cat > /etc/supervisord.d/django-opsweb.ini <<EOF
[program:django-opsweb]
command=/root/.virtualenvs/django-opsweb/bin/gunicorn  -w 4 -k gevent -b 0.0.0.0:8888 ops.wsgi:application --access-logfile /data/django-opsweb/opsweb.log --error-logfile /data/django-opsweb/opsweb.log
directory=/data/django-opsweb
environment=PYTHONPATH='/root/.virtualenvs/django-opsweb/bin'
autostart=true
autorestart=true
user=root
stopasgroup=true
killasgroup=true
redirect_stderr = true
stdout_logfile_maxbytes = 100MB
stdout_logfile_backups = 5
stdout_logfile = /data/django-opsweb/opsweb.log
[program:django-opsweb-daphne]
command=/root/.virtualenvs/django-opsweb/bin/daphne --proxy-headers -b 0.0.0.0 -p 8889 ops.asgi:application --access-log /data/django-opsweb/opsweb.log 
directory=/data/django-opsweb
environment=PYTHONPATH='/root/.virtualenvs/django-opsweb/bin'
autostart=true
autorestart=true
user=root
stopasgroup=true
killasgroup=true
redirect_stderr = true
stdout_logfile_maxbytes = 100MB
stdout_logfile_backups = 5
stdout_logfile = /data/django-opsweb/opsweb.log
EOF

~~~

### nginx 配置  
~~~txt

server{
        listen 80 default_server;
        server_name _;
        return 403;
}

server {
        listen        80; 
        listen        443 ssl;
        server_name   localhost cmdb.devops.com ;
        charset       utf-8;

        ssl_certificate_key server.key;
        ssl_certificate   server.crt;
        ssl_protocols             TLSv1 TLSv1.1 TLSv1.2;

        location / {
                add_header Cache-Control no-store;
                proxy_pass      http://localhost:8888;
                proxy_set_header    Host $host;
                proxy_set_header    X-Real-IP $remote_addr;
                proxy_set_header    X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_read_timeout 20000;
                client_body_buffer_size 102400m;
                client_max_body_size 102400m;
        }
        location /domain_name/ssl_cert/create   {
                proxy_pass          http://localhost:8889;
                proxy_set_header    Upgrade $http_upgrade;
                proxy_set_header    Connection "upgrade";
        }
        location ^~ /static {
                root                    /data/django-opsweb/dist/;
        }
}

~~~

### 其他备注
~~~txt
1./data/django-opsweb/dist/static/admin/ 文件夹是django管理后台静态文件，和vue的静态文件放在一起
ln -s /data/django-opsweb/admin /data/django-opsweb/dist/static/

2.https访问 需要在settings.py 中 配置 CSRF_TRUSTED_ORIGINS 
CSRF_TRUSTED_ORIGINS = ['https://cmdb.devops.com']
 ~~~

### 备份方式
~~~txt
1.备份服务器从opsweb上下载最新备份数据
curl --insecure -X POST https://cmdb.devops.com/download_file  -d  '{"user":"backup","token":"b@tXG#(jy7FgUOciu$"}' -LOJ
~~~
 
### 备案检测部署
~~~txt
1.部署ICP检测服务  
yum -y install golang
cd /data/ && git clone https://github.com/fghwett/icp.git  && go build

cat > /etc/supervisord.d/icp.ini  <<EOF 
[program:icp]
command=/data/icp/icp -port 2080
directory=/data/icp/
autostart=true
autorestart=true
user=root
user = root
; 确保子进程都正确停止
stopasgroup=true
killasgroup=true
redirect_stderr = true
; stdout日志文件大小, 默认: 50MB
stdout_logfile_maxbytes = 100MB
; stdout日志文件备份数
stdout_logfile_backups = 5
; stdout 日志文件，需要注意当指定目录不存在时无法正常启动，所以需要手动创建目录（supervisord 会自动创建日志文件）
stdout_logfile = /var/log/dockerpssupervisord.log
EOF

~~~
