import time

import functions
import essentials
import certificate

def subdomain(url, file, filter_status_code=[], ua_status=False, timeout=10, SSL=True, proxies=None, interval=0, advanced=False, cert=False):
    
    subdomain_json = 'subdomain.json'
    headers_metadata = {}
    cert_metadata = {}

    payloads = essentials.fileReader(file)
    if not payloads:
        print(f'[-] Nao encontrado: {file}')
        return False, f'[-] Nao encontrado: {file}'
    
    for payload in payloads:

        payload = payload.strip()
        test_url = f'https://{payload}.{url}'
        
        time.sleep(interval) # intervalo entre requisicoes
        
        try:
            status, r = functions.request(test_url, ua_status=ua_status, timeout=timeout, 
                                            SSL=SSL, proxies=proxies) # requisicao
        except Exception as err:
            if 'LocationParseError' in str(err):
                if len(filter_status_code) == 0 or 404 in filter_status_code:
                    print(f'[-]{functions.time_now()}{404}{test_url} -> {err}') # filtra erros de parse ex: vazio ou muito longo
                else:
                    print(f'[-]{functions.time_now()}{404}{test_url} -> {err}')
                # colocar o log aqui fara que independentemente do status filtrado, ele seja retornado
                json_obj_response = {
                    'hostname': url,
                    'payload': payload,
                    'url': test_url,
                    'status_code': 404,
                    'error': True,
                    'error_details': err,
                    'date_time': functions.time_now(),
                    'response_headers': {},
                    'response_certificate':{},
                }
                essentials.json_write(json_obj_response, subdomain_json)
            continue
        
        if status:
            if len(filter_status_code) == 0 or (len(filter_status_code) > 0 and r.status_code in filter_status_code):
                print(f'[+][{functions.time_now()}][{r.status_code}] {r.url}')
                if advanced:
                    headers_lowercase = {key.lower(): value.lower() for key, value in r.headers.items()}
                    headers_metadata = {
                        'url': r.url,
                        'server': headers_lowercase.get('server', 'Unknown'),
                        'content-encoding': headers_lowercase.get('content-encoding', 'Unknown'),
                        'content-type': headers_lowercase.get('content-type', 'Unknown'),
                        'cache-control': headers_lowercase.get('cache-control', 'Unknown'),
                    }
                    print(f'{" "*3}[+]{headers_metadata}')
                
                if cert:
                    cert_metadata = certificate.certificate_vulnerability(f'{payload}.{url}')
                    print(f'{" "*3}[+]{cert_metadata}')
        
        else:
            if 'NameResolutionError' in str(r): # filtra erros de dns, como impossibilidade na resolucao
                if len(filter_status_code) == 0 or 404 in filter_status_code:
                    print(f'[-][{functions.time_now()}][404] {r}')
            else:
                if len(filter_status_code) == 0 or 404 in filter_status_code:
                    print(f'[-][{functions.time_now()}][404] {r}')
            
        json_obj_response = {
            'hostname': url,
            'payload': payload,
            'url': test_url,
            'status_code': r.status_code if status else 404,
            'error': False if status else True,
            'error_details': None if status else r,
            'date_time': functions.time_now(),
            'response_headers': headers_metadata if advanced else {},
            'response_certificate': cert_metadata if cert else {},
        }
        essentials.json_write(json_obj_response, subdomain_json)


# Exemplo de uso
subdomain('sodexo.com', 'wordlists/subdomain/wordlist.txt', filter_status_code=[], 
            ua_status=True, timeout=10, advanced=True, cert=True)

# ERROS:
'''
raise LocationParseError(f"'{host}', label empty or too long") from None
urllib3.exceptions.LocationParseError: Failed to parse: 'm..sodexo.com', label empty or too long
'''