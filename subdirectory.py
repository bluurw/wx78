from datetime import datetime as dt
import time

import functions

def subdirectory(url, file, filter_status_code=[], timeout=10, SSL=True, redirect=False, proxies=None, interval=0):

    # colocar um intervalo randomico
    # colocar um gerador de user-agent randomico
    # alterar o test_url para que aceite http tambem
    # verificar como retornar dados do ssl

    payloads = functions.fileReader(file)
    if not payloads:
        print(f'[-] Nao encontrado: {file}')
        return False, f'[-] Nao encontrado: {file}'
    
    for payload in payloads:
        payload = payload.strip()
        test_url = f'{url}/{payload}'.replace('//', '/')
        test_url = 'https://' + test_url
        
        time.sleep(interval) # intervalo entre requisicoes
        time_now = dt.now().strftime('%d/%m/%Y %H:%M:%S') # hora atual
        # requisicao
        status, r = functions.request(test_url, timeout=timeout, SSL=SSL, redirect=redirect, proxies=proxies) 
        
        if status:
            if len(filter_status_code) == 0 or (len(filter_status_code) > 0 and r.status_code in filter_status_code):
                print(f'[+][{time_now}][{r.status_code}] {r.url}')
        else:
            print(f'[-][{time_now}] {r}')


# Example use
subdirectory('pluxee.com.br',
            'wordlists/subdirectory/wordlist.txt',
            timeout=10,
            redirect=True,
            proxies=None, 
            )
