#!/usr/bin/env python3 
# -*- coding:utf-8 _*-  
""" 
@author: Marathon 
@license: Apache Licence 
@file: wangsu_cloud.py
@time: 2022/07/01
@contact: jsdymarathon@itcom888.com
@software: PyCharm 

# 网宿CDN接口
# 1. 缓存刷新
# 2. 域名配置信息
"""

import datetime
from hashlib import sha256
import hmac
import base64
import requests
import json
import time
import traceback


class WangsuCDNApi:
    def __init__(self, _username: str, _apikey: str):
        self._username = _username
        self._apikey = _apikey
        self._date = self.get_date()
        self._accept = "application/json"
        self._api_host = "https://open.chinanetcenter.com"
        self._headers = self.create_header()

    @staticmethod
    def get_date():
        GMT_FORMAT = '%a, %d %b %Y %H:%M:%S GMT'
        date_gmt = datetime.datetime.utcnow().strftime(GMT_FORMAT)
        return date_gmt

    def get_auth(self):
        signed_apikey = hmac.new(self._apikey.encode('utf-8'), self._date.encode('utf-8'), sha256).digest()
        signed_apikey = base64.b64encode(signed_apikey)
        signed_apikey = f'{self._username}:{signed_apikey.decode()}'
        signed_apikey = base64.b64encode(signed_apikey.encode('utf-8'))
        return signed_apikey

    def create_header(self):
        _headers = {
            'Date': self._date,
            'Accept': self._accept,
            'Content-type': self._accept,
            'Authorization': f'Basic {self.get_auth().decode()}'
        }
        return _headers

    def query_domain_config(self, _domain_name: str, _config_tag: str):
        """查询域名配置信息
        :param _domain_name: 要查询的域名
        :param _config_tag: 要查询的配置项
        """
        _api_path = f"/api/domain/{_domain_name}"
        _api_url = f"{self._api_host}{_api_path}"
        try:
            resp = requests.get(_api_url, headers=self._headers)
            resp_data = json.loads(resp.text)
            origin_ips = resp_data.get(_config_tag).get('origin-ips').split(';')
            resp_data[_config_tag]['origin-ips'] = origin_ips
            print(json.dumps(resp_data.get(_config_tag), indent=4))
            return resp_data.get(_config_tag)
        except Exception as e:
            print(traceback.format_exc(e))

    def create_refresh(self, _urls: list):
        """创建缓存刷新任务
        :param _urls: 要刷新的URL列表, 需为同步类弄,如 目录刷新 所URL需为/结尾
        :return _task_id 刷新任务ID
        """
        _api_path = "/ccm/purge/ItemIdReceiver"
        _api_url = f"{self._api_host}{_api_path}"
        _body = {
            'dirs': _urls,
            'dirAction': 'delete'
        }
        try:
            resp = requests.post(_api_url, data=json.dumps(_body), headers=self._headers)
            resp_data = json.loads(resp.text)
            print(f'\t{resp_data}')
            _task_id = resp_data.get('itemId')
            return _task_id
        except Exception as e:
            print(e)

    def query_task_status(self, _task_id: str):
        """查询缓存刷新任务
        :param _task_id 任务ID
        :return _task_status 任务状态
        """
        _api_path = "/ccm/purge/ItemIdQuery"
        _api_url = f'{self._api_host}{_api_path}'
        _body = {'itemId': _task_id}

        try:
            resp = requests.post(_api_url, data=json.dumps(_body), headers=self._headers)
            resp_data = json.loads(resp.text)
            _status = resp_data.get('resultDetail')[0].get('status')
            return _status
        except Exception as e:
            print(e)

    def exce_cdn_cache_refresh_task(self, _domain_name: str, _uri: str):
        """执行缓存刷新任务
        :param _domain_name: 要刷新的域名
        :param _uri 要刷新的URI,多个以','分隔
        """
        _uri_list = _uri.split(',')
        _url_list = [f'https://{_domain_name}{i}' for i in _uri_list]

        print(f'>>> 开始刷新 WangsuCDN 缓存 ...\n\tURL: {_url_list}')
        _task_id = self.create_refresh(_url_list)
        time.sleep(3)  # 任务创建后先等3秒,避免查不到任务
        if _task_id:
            print(f'\n>>> 查询任务[{_task_id}]刷新进度: ...')
            while True:
                query_ret = self.query_task_status(_task_id)
                if query_ret == "success":
                    print('\n### 刷新完成!\n')
                    return "刷新完成"
                elif query_ret == "wait":
                    print('\t+++ 正在刷新中,请稍等 +++')
                    time.sleep(10)
                elif query_ret == "failure":
                    print('\nXXX 刷新失败!\n')
                    return "刷新失败"


if __name__ == '__main__':
    # 帐号名称
    test_username = 'xxxxxx'
    # apikey
    test_apikey = 'xxxxx'
    test_domain = 'www.baidu.com'
    test_uri = '/abc/'
    # 接口实例化
    wangsu_client = WangsuCDNApi(test_username, test_apikey)
    # 示例1. 刷新缓存
    # wangsu_client.exce_cdn_cache_refresh_task(test_domain, test_uri)
    # 示例2. 查询源站信息
    wangsu_client.query_domain_config(test_domain, 'origin-config')

