import asyncio
import socket
import whois

# host -> nome do host/domain str()
def get_ip_host(host):
    try:
        full_info = socket.gethostbyname_ex(host)
        return True, full_info[2]
    except socket.gaierror:
        return False, 'Erro ao obter ip'
    except Exception as e:
        return False, f'Qualquer erro foi retornado {e}'

# domain -> recebe host/domain str()
def get_whois(domain):
    try:
        inquiry = whois.whois(domain)
        return True, inquiry
    except Exception as e:
        return False, f'Erro ao consultar informacoes do dominio {e}'

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