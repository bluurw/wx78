import requests

import functions

# recebe uma url por vez
def sqli(url: str, file: str, timeout=10, proxies=None):
    
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
        test_url = f'{url}?{payload}'
        try:
            r = requests.get(test_url, timeout=timeout, proxies=proxies)
            for error in sql_errors:
                if error.lower() in r.text.lower():
                    print(f'[+] Possível vulnerabilidade: {url} -> {payload}')
                    return True, r.url
        
        except requests.exceptions.Timeout as timeout_error:
            print(f'[-] Tempo limite de requisicao atingido: {r.url}')
            continue
        
        except requests.RequestException as e:
            print(f'[-] Erro ao tentar o payload: {payload} - {e}')
            continue
    
    return False, '[-] Nenhuma vulnerabilidade encontrada'

'''
# Exemplo de uso:
def __name__ == '__main__':
    url = 'http://example.com/vulnerable_page'
    file = "payloads"

    is_vulnerable = sqli(url, file)
    if is_vulnerable:
        print("O site é vulnerável!")
    else:
        print("Nenhuma vulnerabilidade encontrada.")
'''