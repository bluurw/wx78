import requests

def request(url, timeout, SSL, redirect=True, proxies):
    try:
        # request
        r = requests.get(
            url, 
            timeout=timeout,
            verify= SSL,
            allow_redirects = redirect,
            proxies=proxies,
        )
        return True, r
    
    except requests.exceptions.Timeout as timeout_error:
        return False, f'Tempo limite de requisicao atingido: {r.url} - {timeout}s'
        
    except requests.RequestException as e:
        return False, f'Erro ao tentar requisitar: {r.url} - {e}'


def fileReader(file):    
    try:
        with open(f'{file}', 'r') as f:
            lines = f.readlines()
            return lines
    except FileNotFoundError:
        return False