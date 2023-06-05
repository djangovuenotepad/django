import time, json, requests

def sendmsg2mango(group, msg):
    return  msg

opsweb_url = "https://prod.opsweb.obg.com"
query_icp_url = "http://localhost:2080/query?domain="
_key = {"opskey": "654321"}
_all_icp_domains = requests.post(opsweb_url + "/get_icp_domains", data=json.dumps(_key), verify=False).json()['msg']
data = {}
for i in _all_icp_domains:
    time.sleep(5)
    check_status = requests.get(f"{query_icp_url}{i}").json()
    for _check_frequency in range(0, 10):
        if check_status.get("code") == -1:
            print(time.strftime("%F_%Hh_%Mm",time.localtime(time.time())),f"域名{i} 查询频繁暂停20秒")
            time.sleep(20)
            check_status = requests.get(f"{query_icp_url}{i}").json()
        else:
            print(time.strftime("%F_%Hh_%Mm", time.localtime(time.time())), i, check_status)
            break
    # 多次检测频繁 域名数据为获上次检测数据
    if check_status.get("code") == -1:
        _r_data_domain = {"opskey": "654321","domain": i}
        data[i] = requests.post(opsweb_url + "/get_icp_status_last", data=json.dumps(_r_data_domain),verify=False).json()['msg']
    elif check_status.get('data')['isRecorded']:
        data[i] = {'icp_status': True, 'check_time': time.time(), "mainLicence": check_status.get('data')['mainLicence']}
    else:
        data[i] = {'icp_status': False, 'check_time': time.time()}
        _time = time.strftime("%F %T",time.localtime(time.time()))
        try:
            print(sendmsg2mango('notice',f'备案异常: {i}\n检测时间:{_time}'))
        except Exception as err:
            print(err)
print(requests.post(opsweb_url + "/update_icp_domains", data=json.dumps({"opskey": "654321","data": data}),verify=False).json())

