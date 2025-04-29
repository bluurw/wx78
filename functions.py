import asyncio

import requests
from datetime import datetime as dt

import useragent

async def request(url, timeout, SSL, proxies=None, headers=None, ua_status=False, redirect=False, try_requests=1):
    while try_requests > 0:
        if ua_status:
            ua = useragent
            headers = {'User-Agent':ua.get_useragent_experimental()}
        try:
            r = requests.get(
                url,
                headers=headers,
                timeout=timeout,
                verify=SSL,
                allow_redirects=redirect,
                proxies=proxies,
            )
            return True, r
        
        except requests.exceptions.Timeout:
            return False, f'Tempo limite de requisição atingido: {url} t={timeout}s'
        except requests.exceptions.ConnectionError as e:
            return False, f'Erro de conexão: {url} - {e}'
        except requests.exceptions.RequestException as e:
            return False, f'Erro de requisição: {url} - {e}'
        except requests.exceptions.SSLError as e:
            return False, f'Erro de certificado: {url} - {e}'
        try_requests -= 1


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

# fazer um leitor de html para coletar dados sobre a tecnologia usada no site

# criar um sistema que verifica possiveis vulnerabilidades no header
# passa parametros e analisa

def time_now():
    return dt.now().strftime('%d/%m/%Y %H:%M:%S') # hora atual