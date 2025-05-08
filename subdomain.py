import asyncio

import utils
import jsonlog
import commons
import certificate

async def subdomain(origin, file, filter_status_code=[], headers=None, ua_status=False, cookies=None, timeout=10, SSL=True, redirect=False, proxies=None, interval=0, advanced=False, try_requests=1):

    # CONSTANTES
    name_save_file = 'subdomain_teste.json'

    status_payload, payloads = await commons.fileReader(file)
    if not status_payload:
        print(f'[-][{commons.time_now()}] {payloads}')
        return False, payloads
    
    # requisicao assincrona
    async def subdomain_async(payloads):
        for payload in payloads:
            # VARIAVEIS
            cert_metadata = {}
            html_sample = ''
            ip = ''
            
            payload = payload.strip()
            url = f"{origin.split('://')[0]}://{payload}.{origin.split('://')[1]}" if origin.startswith('http://') or origin.startswith('https://') else f'https://{payload}.{origin}' if SSL else f'http://{payload}.{origin}'

            await asyncio.sleep(interval)
            
            print(f'[+][{commons.time_now()}] Testando: {url}')
            status, r = commons.request(url=url, timeout=timeout, SSL=SSL, proxies=proxies, headers=headers, 
                                        ua_status=ua_status, cookies=cookies, redirect=redirect, try_requests=try_requests)
            
            if status:
                if len(filter_status_code) == 0 or (len(filter_status_code) != 0 and r.status_code in filter_status_code):
                    print(f'{" "*3}[>][{commons.time_now()}][{r.status_code}] {url}')
                
                #$ Amostra de codigo e historico de redirect sera coletada somente neste caso (removido)
                if advanced:
                    cert_metadata = await certificate.certificate_vulnerability(url) # verifica se ha vulnerabilidade no certificado
                    #if sample:
                    html_sample = r.text if r.status_code in [301, 302, 307] else r.text[:500]
                    redirect_history = [resp for resp in r.history if resp.status_code in [301, 302, 307]]    
                
                # ip sera coletado por padrao
                status_ip, ip = utils.get_ip_host("".join(url[1:]))
            
            else:
                if len(filter_status_code) == 0 or (len(filter_status_code) != 0 and 404 in filter_status_code):
                    print(f'{" "*3}[>][{commons.time_now()}][404] {url}: {r}')
               
                
            # transforma em json object
            json_obj_response = jsonlog.ObjectJsonCommon.from_data(domain=origin, payload=payload, url=url, ip=ip, r=r, cert_metadata=cert_metadata, html_sample=html_sample)
            write = await jsonlog.AsyncLogger(name_save_file).json_write(json_obj_response)

        return True, f'[+] Wordlist concluido: {file} & Gerado arquivo: {name_save_file}'
    
    await subdomain_async(payloads) # executa todo o loop e aguarda

            
# Attack
async def main(origin, file, filter_status_code=[], headers=None, ua_status=False, cookies=None, timeout=10, SSL=True, redirect=False, proxies=None, interval=0, advanced=False, try_requests=1):
    try:
        status, attk = await subdomain(origin, file, filter_status_code, headers, ua_status, cookies, timeout, SSL, redirect, proxies, interval, advanced, try_requests)
        if status:
            return True, f'[#] Execucao finalizada'
        else:
            return False, f'[#] Execucao finalizada por erro {attk}'
    except TypeError:
        return False, f'[#] Um erro de tipagem surgiu'
    except Exception as err:
        return False, f'[#] Um erro surgiu & a execucao foi interrompida {err}'