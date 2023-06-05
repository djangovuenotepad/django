import requests, pprint, json, time


def edit(_token, portal_address, env, appId, key, value,comment):
    data = {
        "key": key,
        "value": value,
        "comment": comment,
        "dataChangeLastModifiedBy": "apollo"
    }
    headers = {"Authorization": _token, "Content-Type": "application/json"}
    url = f'http://{portal_address}/openapi/v1/envs/{env}/apps/{appId}/clusters/default/namespaces/application/items/{key}'
    status = requests.put(url, headers=headers, data=json.dumps(data)).status_code
    return status


def release(_token, portal_address, env, appId):
    data = {
        "releaseTitle": time.strftime("%F-%T", time.localtime(time.time())),
        "releaseComment": "opsweb调用",
        "releasedBy": "apollo"}

    headers = {"Authorization": _token, "Content-Type": "application/json"}
    url = f'http://{portal_address}/openapi/v1/envs/{env}/apps/{appId}/clusters/default/namespaces/application/releases'
    status = requests.post(url, headers=headers, data=json.dumps(data)).status_code
    return status


def pull(_token, portal_address, env, appId):
    headers = {"Authorization": _token, "Content-Type": "application/json"}
    url = f'http://{portal_address}/openapi/v1/envs/{env}/apps/{appId}/clusters/default/namespaces/application'
    status = requests.get(url, headers=headers).json()
    return status['items']


if __name__ == "__main__":
    conf = {'c': {'token': '***',
                  'domain': "apollo.***.com",
                  'env': "DEV",
                  'appId': "ops",
                  'user': "apollo"}
            }
    _token = conf['c']['token']
    portal_address = conf['c']['domain']
    env = conf['c']['env']
    appId = conf['c']['appId']


    #  后台配置模板
    ''' 
        {   'appId': 'ops',
        'domain': 'apollo.ccccc.com:8070',
        'env': 'DEV',
        'key': ['game.domains',  ],
        'token': 'asdfasfsafasfas',
        'user': 'apollo'}
    '''

    # 编辑 apollo
    value = json.dumps({"mainland": "https://www.jd.com", "dongnanya": "https://taobao.com"})
    pprint.pprint(edit(_token, portal_address, env, appId, "opsops", value,''), indent=4)

    # 发布 apollo
    pprint.pprint(release(_token, portal_address, env, appId), indent=4)

    # 拉取 apollo 数据
    pprint.pprint(pull(_token, portal_address, env, appId), indent=4)
