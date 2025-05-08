import asyncio

import utils
import jsonlog
import commons
import certificate
import HTMLAnalitcs

async def subdirectory(target, wordlist_file, save_file, filter_status_code, headers, ua_status, cookies, timeout, SSL, redirect, proxies, interval, advanced, try_requests, verbose):

    # CONSTANTES
    save_file = save_file if save_file.endswith('.json') else f'{save_file.rsplit(".", 1)[0]}.json'

    status_payload, payloads = await commons.fileReader(wordlist_file)
    if not status_payload:
        print(f'[#][{commons.time_now()}] {payloads}')
        return False, payloads
    
    # requisicao assincrona
    async def subdirectory_async(payloads):
        for payload in payloads:
            # VARIAVEIS
            #get_all_path(r)
            #get_all_url(r)
            html_sample = ''
            details = {}
            ip = ''
            
            payload = payload.strip()
            target_ = target if target.endswith('/') else target + '/'
            url = f"{target_.split('://')[0]}://{target_.split('://')[1]}{payload}" if target_.startswith('http://') or target_.startswith('https://') else f'https://{target_}{payload}' if SSL else f'http://{target_}{payload}'

            await asyncio.sleep(interval)

            if verbose:
                print(f'[+][{commons.time_now()}] Testando: {url}')
            status, r = commons.request(url=url, timeout=timeout, SSL=SSL, proxies=proxies, headers=headers, 
                                        ua_status=ua_status, cookies=cookies, redirect=redirect, try_requests=try_requests)
            
            if status:
                if len(filter_status_code) == 0 or (len(filter_status_code) != 0 and r.status_code in filter_status_code):
                    print(f'{" "*3}[>][{commons.time_now()}][{r.status_code}] {url}')
                
                #$ Amostra de codigo e historico de redirect sera coletada somente neste caso (removido)
                if advanced:
                    cert_metadata = await certificate.certificate_vulnerability(url) # verifica se ha vulnerabilidade no certificado
                    html_sample = r.text if r.status_code in [301, 302, 307] else r.text[:500]
                    redirect_history = [resp for resp in r.history if resp.status_code in [301, 302, 307]]

                    details['urls'] = HTMLAnalitcs.get_all_url(r)
                    details['paths'] = HTMLAnalitcs.get_all_path(r)
                
                # ip sera coletado por padrao
                status_ip, ip = utils.get_ip_host("".join(url[1:]))
            
            else:
                if len(filter_status_code) == 0 or (len(filter_status_code) != 0 and 404 in filter_status_code):
                    print(f'{" "*3}[>][{commons.time_now()}][404] {url}: {r}')
               
                
            # transforma em json object
            json_obj_response = jsonlog.ObjectJsonCommon.from_data(target, payload, url, ip, r, cert_metadata, html_sample)
            write = await jsonlog.AsyncLogger(save_file).json_write(json_obj_response)

        return True, f'[#] Wordlist concluido: {wordlist_file} & Gerado arquivo: {save_file}'
    
    await subdirectory_async(payloads) # executa todo o loop e aguarda




# Attack
async def main(target, wordlist_file, save_file='subdirectory_teste.json', filter_status_code=[], headers=None, ua_status=False, cookies=None, timeout=10, SSL=True, redirect=False, proxies=None, interval=0, advanced=False, try_requests=1, verbose=True):
    # Criar validacao para arquivos vazios
    try:
        status, attk = await subdirectory(target, wordlist_file, save_file, filter_status_code, headers, ua_status, cookies, timeout, SSL, redirect, proxies, interval, advanced, try_requests, verbose)
        if status:
            return True, f'[#] Execucao finalizada'
        else:
            return False, f'[#] Execucao finalizada por erro {attk}'
    except TypeError:
        return False, f'[#] Um erro de tipagem surgiu'
    except Exception as err:
        return False, f'[#] Um erro surgiu & a execucao foi interrompida {err}'