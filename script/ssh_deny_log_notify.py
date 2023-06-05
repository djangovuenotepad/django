import requests, json, time


def sendmsg2mango(group, msg):
   return  msg


now_time = time.strftime("%F_%T", time.localtime(time.time()))

try:
    data = requests.post("http://ssh_deny_log.com/ssh_deny_log", data={"day": 1}).content
    _data = json.loads(data)
    if _data['status'] == 200:

        all_log = []
        _all_log_count =[]
        for i in _data['msg']:
            t1 = i['信息'].split()[0]
            t2 = i['信息'].split()[1]
            ssh_deny_time = time.mktime(time.strptime(f'{t1}{t2}', "%Y-%m-%d%H:%M:%S"))
            if time.time() - ssh_deny_time < 1800:
                all_log.append(str(i))
        log_total = len(all_log)
        if log_total >= 5:
            _log = '\n'.join(all_log[-5:])
        else:
            _log = '\n'.join(all_log)
        for _project in _data["log_count"]:
            for _project_log in _project:
                _all_log_count.append(f'{_project_log}  {str(_project[_project_log])}')
        _count_log = '\n'.join(_all_log_count)
        send_msg = f'''💔 💔 半小时内检索到异常日志 {log_total}  条:\n💔 💔 1天内各项目异常日志统计：\n{_count_log}\n\n{_log}\n\n详细记录查询opsweb'''
        if log_total > 0:
            print(now_time, sendmsg2mango('notice', send_msg))
        else:
            print(now_time, "没有异常登录日志")
    else:
        raise RuntimeError("QP ssh_deny_log 请求api异常")

except Exception as err:
    print(now_time, sendmsg2mango('notice', f'💔 💔 ssh_deny_log 请求api异常'))
    print(now_time, str(err))
