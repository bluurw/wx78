import asyncio
import aiofiles
from datetime import datetime as dt

import requests
import json

import useragent

# timeout -> tempo maximo aguardando resposta
# ssl -> se https
# method -> metodo de requisicao 
# payload -> carga util
# ua_status -> se true, usa headers aleatorios, se houve algo em header, header sera ignorado.
# redirect -> permite o redirecionamento
# try_requests -> numero maximo de tentativas
def request(url, timeout, SSL, method='GET', payload=None, proxies=None, headers=None, cookies=None, ua_status=False, redirect=False, try_requests=1):
    if not url.startswith('http://') and not url.startswith('https://'):
        url = f'https://{url}' if SSL else f'http://{url}'
    while try_requests > 0:
        if ua_status:
            ua = useragent
            headers_ = {'User-Agent': ua.get_useragent_experimental()}
        elif not ua_status and not headers:
            ua = useragent
            headers_ = {'User-Agent': ua.get_useragent_experimental()}
        else:
            headers_ = headers
        try:
            if method == 'GET' or method == None:
                r = requests.get(
                    url,
                    params=payload,
                    headers=headers_,
                    cookies=cookies,
                    timeout=timeout,
                    verify=SSL,
                    allow_redirects=redirect,
                    proxies=proxies,
                )
            if method == 'POST':
                r = requests.post(
                    url,
                    data=payload,
                    headers=headers_,
                    cookies=cookies,
                    timeout=timeout,
                    verify=SSL,
                    allow_redirects=redirect,
                    proxies=proxies,
                )
            return True, r
        except requests.exceptions.Timeout:
            error_msg = f'Tempo limite de requisição atingido: {url} t={timeout}s'
        except requests.exceptions.ConnectionError as err:
            error_msg = f'Erro de conexão: {url} - {err}'
        except requests.exceptions.RequestException as err:
            error_msg = f'Erro de requisição: {url} - {err}'
        except requests.exceptions.SSLError as err:
            error_msg = f'Erro de certificado: {url} - {err}'
        except:
            error_msg = f'Erro nao documentado encontrado: {url}'
        try_requests -= 1
    return False, error_msg

# le wordlists
# file -> caminho do arquivo
async def fileReader(file):
    try:
        async with aiofiles.open(f'{file}', 'r') as f:
            lines = await f.readlines()
            return True, lines
    except FileNotFoundError:
        return False, 'Arquivo nao encontrado'
    except Exception as err:
        return False, err

def time_now():
    return dt.now().strftime('%d/%m/%Y %H:%M:%S') # hora atual