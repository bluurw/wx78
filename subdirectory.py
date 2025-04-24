import requests
from datetime import datetime as dt
import time

import functions

def subdirectory(url, file, filter_status_code=[], timeout=10, SSL=True, proxies=None, interval=0, advanced=False):

    payloads = functions.fileReader(file)
    if not payloads:
        print(f'[-] Nao encontrado: {file}')
        return False, f'[-] Nao encontrado: {file}'
    
    for payload in payloads:
        payload = payload.strip()
        test_url = f'{url}/{payload}'.replace('//', '/')
        test_url = 'https://' + test_url
        try:
            time.sleep(interval)
            # request
            r = requests.get(
                test_url, 
                timeout=timeout,
                verify= SSL,
                proxies=proxies,
            )
            time_now = dt.now().strftime('%d/%m/%Y %H:%M:%S')
            if len(filter_status_code) == 0 or (len(filter_status_code) > 0 and r.status_code in filter_status_code):
                print(f'[+][{time_now}][{r.status_code}] {r.url}')
                if advanced:
                    headers_lowercase = {key.lower(): value.lower() for key, value in r.headers.items()}
                    metadata = {
                        'url': r.url,
                        'server': headers_lowercase.get('server', 'Unknown'),
                        'content-encoding': headers_lowercase.get('content-encoding', 'Unknown'),
                        'content-type': headers_lowercase.get('content-type', 'Unknown'),
                        'cache-control': headers_lowercase.get('cache-control', 'Unknown'),
                    }
                    print(f'[+]{" "*3}{metadata}')
        
        except requests.exceptions.Timeout as timeout_error:
            print(f'[-][{time_now}] Tempo limite de requisicao atingido: {r.url}')
            continue
        
        except requests.RequestException as e:
            print(f'[-][{time_now}] Erro ao tentar o payload: {url} {payload} - {e}')
            continue



# Example use
subdirectory('pluxee.com.br',
            '/home/maserati/Downloads/Python/wx78/wordlists/subdirectory/wordlist.txt',
            timeout=10,
            proxies=None, 
            advanced=True)
    
