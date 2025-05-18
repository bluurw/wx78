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


# response -> resposta bruta da requisicao
async def test_waf_detection(response):
    import re
    
    waf_vendors = [
        'cloudflare', 'sucuri', 'akamai', 'imperva', 'incapsula', 'barracuda',
        'f5 big-ip', 'aws', 'amazon cloudfront', 'fastly', 'edgecast', 'stackpath',
        'radware', 'druva', 'nsfocus', 'fortinet', 'fortiweb', 'citrix', 'cdn77',
        'qualys', 'netscaler', 'bluedon', 'dotdefender', 'alert logic', 'trustwave',
        'denyall', 'oracle cloud', 'shield square', 'reblaze', 'akamai ghost',
        'wangsu', 'yundun', 'baidu yunjiasu', 'aliyun', '360 web application firewall',
        'tencent cloud', 'neustar', 'arbor networks', 'securitydam', 'big-ip',
        'bitninja', 'binarysec', 'sqreen', 'china cache', 'azion', 'onapp', 'rsfirewall',
        'modsecurity', 'airlock', 'profense', 'webseal', 'edge security', 'zeus'
    ]

    waf_status_code = [
        400, 401, 403, 404, 406, 408, 409, 411, 413, 414, 418, 429, 451,
        502, 503, 509, 510, 511
    ]

    waf_redirects = ['/error', '/security-check', '/blocked', '/captcha', '/challenge']

    waf_block_phrases = [
        'access denied', 'request blocked', '403 forbidden', 'not allowed',
        'waf', 'web application firewall', 'security check', 'malicious request',
        'you have been blocked', 'denied by policy', 'suspicious activity',
        'your request looks automated', 'ddos protection by', 'protection mode is enabled'
    ]

    waf_headers = [
        'x-sucuri-id', 'cf-ray', 'x-akamai-transformed', 'x-cdn',
        'x-barracuda', 'x-imperva-id', 'x-imperva-block-id', 'x-incapsula',
        'x-distil-cs', 'x-sitelock', 'x-dotdefender-denied', 'x-ddos-filter',
        'x-waf-event', 'x-fireeye', 'x-f5', 'server-timing', 'x-azure-ref'
    ]

    waf_cookies = [
        '__cfduid', '__cf_bm', 'incap_ses_', 'visid_incap_', 'awsalb', 'awsalbcors',
        'bigipserver', 'f5avr', 'f5_cspm', 'sucuri_cloudproxy_uuid_', 'ts', 'citrix_ns_id'
    ]

    responder_headers = [k.lower() for k in response.headers.keys()]
    responder_cookies = [c.lower() for c in response.cookies.keys()]
    server_header = response.headers.get('server', '').lower()
    location_header = response.headers.get('location', '').lower()
    response_text = response.text.lower()

    block_regex = re.compile(
        r"(access\s+denied|request\s+blocked|403\s+forbidden|web\s+application\s+firewall|"
        r"suspicious\s+activity|protection\s+mode\s+is\s+enabled|ddos\s+protection\s+by)",
        re.I
    )

    # DETECT TYPE WAF
    detected_waf = None

    for waf in waf_vendors:
        if waf in server_header:
            detected_waf = waf
            break

    if not detected_waf:
        for header in responder_headers:
            if any(waf in header for waf in waf_vendors):
                detected_waf = next((waf for waf in waf_vendors if waf in header), None)
                break

    if not detected_waf:
        for cookie in responder_cookies:
            if any(waf in cookie for waf in waf_vendors):
                detected_waf = next((waf for waf in waf_vendors if waf in cookie), None)
                break

    waf_possibility = {
        'server': 10 if detected_waf else 0,
        'status_code': 3 if response.status_code in waf_status_code else 0,
        'location_redirect': 10 if any(location_header.startswith(r) for r in waf_redirects) else 0,
        'block_phrases': 5 if block_regex.search(response_text) else 0,
        'headers': 5 if any(h in responder_headers for h in waf_headers) else 0,
        'cookies': 5 if any(c in responder_cookies for c in waf_cookies) else 0,
        'js_challenge': 5 if 'document.cookie' in response_text and 'settimeout' in response_text else 0,
        'meta_refresh': 3 if '<meta http-equiv="refresh"' in response_text else 0
    }

    score = sum(waf_possibility.values())
    waf_detected = score >= 10

    return {
        'waf_detected': waf_detected,
        'score': score,
        'matches': {k: v for k, v in waf_possibility.items() if v > 0},
        'waf_name': detected_waf
    }




# EXAMPLE USE
# print(get_ip_host('https://example.com'))