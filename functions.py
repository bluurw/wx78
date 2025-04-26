from datetime import datetime as dt
import requests

import useragent # gera headers

def request(url, timeout, SSL, proxies=None, headers=None, ua_status=False, redirect=False, try_requests=1):
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
            if r.status_code == 200:
                return True, r
            else:
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

def time_now():
    return dt.now().strftime('%d/%m/%Y %H:%M:%S') # hora atual