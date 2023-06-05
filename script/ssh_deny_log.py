# -!- coding=gbk -!-
from flask import Flask, request
import elasticsearch, datetime

'''
		pip3 install elasticsearch==6.8.2

'''

app = Flask(__name__)


@app.route("/ssh_deny_log", methods=['POST'])
def SSH_DENY_LOG():
    try:
        _day = request.form.get('day', 7)
        es_conf = [{"project": "game", "ip": "192.168.1.223", "port": "9200", "password": "********"}, ]

        lte = datetime.datetime.now().isoformat() + "+0800"
        if int(_day) == 0:
            td = datetime.timedelta(minutes=60, seconds=10, microseconds=0)
        else:
            td = datetime.timedelta(days=int(_day), seconds=10, microseconds=0)
        gte = (datetime.datetime.now() - td).isoformat() + "+0800"
        body = {"query": {"range": {"@timestamp": {
            "gte": gte, "lte": lte,
            "format": "strict_date_optional_time"}}}}
        data = []
        log_count = []
        for i in es_conf:
            es = elasticsearch.Elasticsearch([{"host": i["ip"], "port": i["port"]}],
                                             http_auth=("elastic", i["password"]), sniff_on_start=True)
            es_data = es.search(index='ssh_deny_log-*',scroll='5m', body=body, size=10000)
            log_count.append({i['project']: es_data['hits']['total']['value']})
            data += es_data['hits']['hits']
            if not es_data.get("_scroll_id"):
                continue
            scroll_id = es_data['_scroll_id']
            total = es_data['hits']['total']['value']
            for i in range(total // 10000):
                res = es.scroll(scroll_id=scroll_id, scroll='5m')
                data += res['hits']['hits']


        msg = []
        for i in data:
            msg.append({"日志": i['_index'], "服务器": i['_source']['fields']['ip'], "信息": i['_source']['message']})
        return {"msg": msg, "log_count": log_count, "status": 200}
    except Exception as err:
        return {"msg": str(err), "status": 5001}


if __name__ == '__main__':
    app.run(host='localhost', port=9201)
    '''  获取方式
    import requests,json
    msg=requests.post("http://localhost:9201/ssh_deny_log",data={"day":3}).content
    json.loads(msg)
    '''
