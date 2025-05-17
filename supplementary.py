import socket
import whois


# response_headers -> recebe o headers como entrada {}
async def get_headers_metadata(response_headers):
    if 'CaseInsensitiveDict' in str(type(response_headers)):
        headers_lowercase = {key.lower(): value.lower() for key, value in response_headers.items()}
        headers_metadata = {
            'access-control-allow-credentials': headers_lowercase.get('access-control-allow-credentials', 'Unknown'), # indica login
            'access-control-allow-headers': headers_lowercase.get('access-control-allow-headers', 'Unknown'),
            'access-control-allow-methods': headers_lowercase.get('access-control-allow-methods', 'Unknown'),
            'access-control-allow-origin': headers_lowercase.get('access-control-allow-origin', 'Unknown'),
            'cache-control': headers_lowercase.get('cache-control', 'Unknown'),
            'content-encoding': headers_lowercase.get('content-encoding', 'Unknown'),
            'content-type': headers_lowercase.get('content-type', 'Unknown'),
            'etag': headers_lowercase.get('etag', 'Unknown'),
            'content-length': headers_lowercase.get('content-length', 'Unknown'),
            'server': headers_lowercase.get('server', 'Unknown'), # servidor
            'location': headers_lowercase.get('location', 'Unknown'),
            'x-frame-options': headers_lowercase.get('x-frame-options', 'Unknown'), # previne clickjacking, se em falta o site e vulneravel
            'x-matched-path': headers_lowercase.get('x-matched-path', 'Unknown'),
            'x-powered-by': headers_lowercase.get('x-powered-by', 'Unknown'),
            'X-sc-rewrite': headers_lowercase.get('X-sc-rewrite', 'Unknown'),
            'transfer-encoding': headers_lowercase.get('transfer-encoding', 'Unknown'),
            'set-cookie': headers_lowercase.get('set-cookie', 'Unknown'),
        }
        return True, headers_metadata
    else:
        return False, 'dados invalidos'


# host -> nome do host/domain str()
def get_ip_host(hostname):
    hostname = hostname.split('://')[1] if hostname.startswith('http://') or hostname.startswith('https://') else hostname
    print(hostname)
    try:
        full_info = socket.gethostbyname_ex(hostname)
        return True, full_info[2]
    except socket.gaierror:
        return False, 'Erro ao obter ip'
    except Exception as e:
        return False, f'Qualquer erro foi retornado {e}'


# domain -> recebe host/domain str()
def get_whois(hostname):
    hostname = hostname.split('://')[1] if hostname.startswith('http://') or hostname.startswith('https://') else hostname
    try:
        inquiry = whois.whois(hostname)
        return True, inquiry
    except Exception as e:
        return False, f'Erro ao consultar informacoes do dominio {e}'


# hostname -> recebe host/domain str()
def get_dns(hostname):
    dtdns = {}
    hostname_ = hostname.split('://')[1] if hostname.startswith('http://') or hostname.startswith('https://') else hostname
    record_types = sorted([
        'A', 'AAAA', 'ANY', 'CAA', 'CNAME', 'DNSKEY', 'DS',
        'MX', 'NS', 'PTR', 'SOA', 'SRV', 'TLSA', 'TSIG', 'TXT',
    ])
    for type_ in record_types:
        try:
            response = dns.resolver.resolve(hostname_, type_)
            dtdns[type_] = [r.to_text() for r in response]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            dtdns[type_] = 'Sem resposta'
        except dns.resolver.Timeout:
            dtdns[type_] = 'Timeout'
        except Exception as err:
            dtdns[type_] = 'Sem informacao'
    return dtdns


# response -> resposta bruta da requisicao
async def waf_detection(response):
    score = 0
    waf_servers = [
        'cloudflare', 'sucuri', 'akamai', 'imperva', 'incapsula', 'barracuda',
        'f5 big-ip', 'aws', 'amazon cloudfront', 'fastly', 'edgecast', 'stackpath',
        'radware', 'druva', 'nsfocus', 'fortinet', 'fortiweb', 'citrix', 'cdn77',
        'qualys', 'netscaler', 'bluedon', 'dotdefender', 'alert logic', 'trustwave',
        'denyall', 'oracle cloud', 'shield square', 'reblaze', 'akamai ghost',
        'wangsu', 'yundun', 'baidu yunjiasu', 'aliyun', '360 web application firewall',
        'tencent cloud',
    ]
    waf_status_code = [400, 401, 403, 404, 406, 408, 409, 411, 413, 414, 418, 429, 451]
    waf_redirect = ['/error', '/security-check', '/blocked']
    waf_block_phrases = [
        'access denied', 'request blocked', 'forbidden', 'not allowed',
        'waf', 'web application firewall', 'security check', 'malicious request',
        'you have been blocked', 'denied by policy',
    ]
    waf_headers = ['x-sucuri-id', 'cf-ray', 'x-akamai-transformed', 'x-cdn']

    responder_headers = [k.lower() for k in response.headers.keys()]
    
    waf_possibility = {
        'servers': 10 if response.headers.get('server', '').lower() in waf_servers else 0,
        'status_code': 3 if response.status_code in waf_status_code else 0,
        'location': 10 if response.headers.get('location', '').lower() in waf_redirect else 0,
        'block_pharses': 5 if any(pharses.lower() in response.text.lower() for pharses in waf_block_phrases) else 0,
        'headers': 5 if any(term.lower() in responder_headers for term in waf_block_phrases) else 0,
    }
    score += sum(v for v in waf_possibility.values())
    return True if score >= 10 else False


#
# print(get_ip_host('https://example.com'))