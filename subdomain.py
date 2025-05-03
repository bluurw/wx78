import asyncio

import commons
import functions
import jsonlog
import certificate

async def subdomain(origin, file, filter_status_code=[], ua_status=False, timeout=10, SSL=True, redirect=False, proxies=None, interval=0, advanced=False):

    # CONSTANTES
    name_save_file = 'subdomain_teste.json'
    scheme = 'https' if SSL else 'http'

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
            url = f'{scheme}://{payload}.{origin}'

            await asyncio.sleep(interval)

            print(f'[+][{commons.time_now()}] Testando: {url}')
            status, r = commons.request(url, ua_status=ua_status, timeout=timeout,
                                        SSL=SSL, redirect=redirect, proxies=proxies)
            
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
                status_ip, ip = functions.get_ip_host("".join(url[1:]))
            
            else:
                if len(filter_status_code) == 0 or (len(filter_status_code) != 0 and 404 in filter_status_code):
                    print(f'{" "*3}[>][{commons.time_now()}][404] {url}: {r}')
               
                
            # transforma em json object
            json_obj_response = jsonlog.ObjectJson.from_data(domain=origin, payload=payload, url=url, ip=ip, r=r, cert_metadata=cert_metadata, html_sample=html_sample)
            write = await jsonlog.AsyncLogger(name_save_file).json_write(json_obj_response)

        return True, f'[+] Wordlist concluido: {file} & Gerado arquivo: {name_save_file}'
    
    await subdomain_async(payloads) # executa todo o loop e aguarda

            
# Exemplo de uso
async def main():
    await subdomain('socasadas.com', 'wordlists/subdomain/wordlist.txt', filter_status_code=[], ua_status=True, 
                    redirect=False, timeout=10, proxies=None, interval=0, advanced=True)

asyncio.run(main())