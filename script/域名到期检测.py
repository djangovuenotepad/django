import re,requests,json,whois,time
opsweb_url = "https://cmdb.devops.com:1443"
_key = {"opskey": "654321"}
_all_domains = requests.post(opsweb_url + "/get_all_domain", data=json.dumps(_key), verify=False).json()['msg']
data = []
n=0
for i in _all_domains:
    n+=1
    print(n,i)
    try:
        _date = whois.query(i).expiration_date.strftime("%Y-%m-%d")
        registrar = whois.query(i).registrar
    except Exception:
        try:
            w_html = requests.get(f"https://whois.reg.cn/Whois/QueryWhois?domain={i.lower()}&key=23dfw43459835vbffg").text
            _date = re.findall("Registry Expiry Date:(.*?)T", w_html)[0]
            registrar = re.findall(r'注册商：</td>\r\n                                    <td>(.*?)</td>',w_html)[0].split(',')[0]
        except Exception:
            _date = None
            registrar = None
    _time = time.strftime("%F %T", time.localtime(time.time()))
    if time.strftime("%Y-%m", time.localtime(time.time())) in _date or time.strftime("%Y-%m", time.localtime(
            time.time() + 2592000)) in _date:
        status = "faild"
    else:
        status = "success"
    jsdata={"domain": i, "expri_date": _date, "check_time": _time, "registrar": registrar, "status": status}
    data.append(jsdata)
    print(jsdata)
print(requests.post(opsweb_url + "/update_domain_expire", data=json.dumps({"opskey": "654321","data": data}),verify=False).json())