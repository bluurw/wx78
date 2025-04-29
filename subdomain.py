import asyncio

import functions
import essentials
import certificate

async def subdomain(url, file, filter_status_code=[], ua_status=False, timeout=10, SSL=True, proxies=None, interval=0, advanced=False, cert=False):
    
    # sistema que verifica informacoes da tecnologia usada

    payloads = await essentials.fileReader(file) # aguardar a leitura
    if not payloads:
        print(f'[-] Nao encontrado: {file}')
        return False, f'[-] Nao encontrado: {file}'
    
    # requisicao assincrona
    async def subdomain_async(payloads):
        
        name_save_file = 'subdomain.json'
        headers_metadata = {}
        cert_metadata = {}
        scheme = 'https' if SSL else 'http' # define se e http ou https

        for payload in payloads:

            payload = payload.strip()
            test_url = f'{scheme}://{payload}.{url}'
            
            await asyncio.sleep(interval) # intervalo entre requisicoes
            
            try:
                status, r = await functions.request(test_url, ua_status=ua_status, timeout=timeout, 
                                                    SSL=SSL, proxies=proxies) # aguarda a requisicao
            except Exception as err:
                if 'LocationParseError' in str(err):
                    if len(filter_status_code) == 0 or 404 in filter_status_code:
                        print(f'[-]{functions.time_now()}{404}{test_url} -> {err}') # filtra erros de parse ex: vazio ou muito longo
                    else:
                        print(f'[-]{functions.time_now()}{404}{test_url} -> {err}')
                    # colocar o log aqui fara com que, independentemente do status filtrado, ele seja retornado
                    json_obj_response = {
                        'hostname': url,
                        'payload': payload,
                        'url': test_url,
                        'background': None,
                        'details': None,
                        'status_code': 404,
                        'error': True,
                        'error_details': err,
                        'date_time': functions.time_now(),
                        'response_headers': {},
                        'response_certificate':{},
                    }
                    await essentials.json_write(json_obj_response, name_save_file) # aguarda finalizar a escrita
                continue
            
            if status:
                if len(filter_status_code) == 0 or (len(filter_status_code) > 0 and r.status_code in filter_status_code):
                    # headers_metadata = functions.get_headers_metadata(r.headers)
                    print(f'[+][{functions.time_now()}][{r.status_code}] {r.url}')

                    if advanced:
                        print(f'{" "*3}[*]{r.headers}')
                    
                    if cert:
                        cert_metadata = await certificate.certificate_vulnerability(f'{payload}.{url}') # aguarda o retorno do cert
                        print(f'{" "*3}[*]{cert_metadata}')
            
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
                'background': None,
                'details': None,
                'status_code': r.status_code if status else None,
                'error': False if status else True,
                'error_details': None if status else r,
                'date_time': functions.time_now(),
                'response_headers': r.headers if (advanced and status) else {}, # headers_metadata
                'response_certificate': cert_metadata if cert else {},
            }
            await essentials.json_write(json_obj_response, name_save_file)
    
    await subdomain_async(payloads) # executa todo o loop e aguarda
    
    return True, f'[+] Wordlist concluido: {file} & Gerado arquivo: {name_save_file}'


# Exemplo de uso
async def main():
    await subdomain('sodexo.com', 'wordlists/subdomain/wordlist.txt', filter_status_code=[], 
                    ua_status=True, timeout=10, advanced=True, cert=True)

asyncio.run(main())

# ERROS:
'''
raise LocationParseError(f"'{host}', label empty or too long") from None
urllib3.exceptions.LocationParseError: Failed to parse: 'm..sodexo.com', label empty or too long
'''