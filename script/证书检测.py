import idna, time, json, requests
from socket import socket
from OpenSSL import SSL
from urllib import parse


def get_certificate(_cdn, _domain, port):
    hostname_idna = idna.encode(_domain)
    sock = socket()
    sock.connect((_cdn, port), )
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE
    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_connect_state()
    sock_ssl.set_tlsext_host_name(hostname_idna)  # 关键: 对应不同域名的证书
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    sock_ssl.close()
    sock.close()
    return cert


jsdata = '{"opskey":"654321"}'
_alldns = requests.post("https://cmdb.devops.com/get_alldns", data=jsdata, verify=False).json().get('msg')
n = 0
for _dns in _alldns:
    n += 1
    print(f"\n{n} 域名:--------: {_alldns.get(_dns).get('domain')}   CDN:------- {_alldns.get(_dns).get('dns')}")
    try:
        rs = parse.urlparse('https://' + _alldns.get(_dns).get('domain'))
        cert = get_certificate(_alldns.get(_dns).get('dns'), rs.hostname, int(rs.port or 443))
        _start = time.strftime("%Y-%m-%d", time.strptime(cert.get_notBefore().decode(), "%Y%m%d%H%M%SZ"))
        _end = time.strftime("%Y-%m-%d", time.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ"))
        days = int(
            (time.mktime(time.strptime(cert.get_notAfter().decode(), "%Y%m%d%H%M%SZ")) - time.time()) / (60 * 60 * 24))
        data = {"opskey": "654321", "id": _dns, "start": _start, "end": _end, "days": days, 'check_time': time.time(),
                'status': True}
    except Exception as err:
        data = {"opskey": "654321", "id": _dns, 'check_time': time.time(), 'status': str(err)}
    print(f"数据:--- {data}")
    print("opsweb返回结果:--- ",  requests.post("https://cmdb.devops.com/update_dns_ssl", data=json.dumps(data), verify=False).json())
