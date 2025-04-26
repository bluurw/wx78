import time

import functions
import essentials

def subdirectory(url, file, filter_status_code=[], ua_status=False, timeout=10, redirect=False, SSL=True, proxies=None, interval=0):
    
    # alterar o test_url para que aceite http tambem

    subdirectory_json = 'subdirectory.json'

    payloads = essentials.fileReader(file)
    if not payloads:
        print(f'[-] Nao encontrado: {file}')
        return False, f'[-] Nao encontrado: {file}'
    
    for payload in payloads:
        payload = payload.strip()
        test_url = f'{url}/{payload}'.replace('//', '/')
        test_url = 'https://' + test_url
        
        time.sleep(interval) # intervalo entre requisicoes
        # requisicao
        status, r = functions.request(test_url, timeout=timeout, SSL=SSL, 
                                        redirect=redirect, proxies=proxies) 
        if status:
            if len(filter_status_code) == 0 or (len(filter_status_code) > 0 and r.status_code in filter_status_code):
                print(f'[+][{functions.time_now()}][{r.status_code}] {r.url}')
        else:
            print(f'[-][{functions.time_now()}] {r}')
        
        # json nao sera filtrado
        json_obj_response = {
            'hostname': url,
            'payload': payload,
            'url': test_url,
            'status_code': r.status_code if status else 404,
            'error': False if status else True,
            'error_details': None if status else r,
            'date_time': functions.time_now(),
            'response_headers': {},
            'response_certificate':{},
        }
        essentials.json_write(json_obj_response, subdirectory_json)


# Example use
subdirectory('pluxee.com.br', 'wordlists/subdirectory/wordlist.txt', timeout=10, 
                redirect=True, proxies=None)
