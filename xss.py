import asyncio
import random
import re
import html
from bs4 import BeautifulSoup

import utils
import jsonlog
from Request import Request
import HTMLAnalitcs

class XSS:
    def __init__(self, target, wordlist_file='wordlists/xss/default.txt', option='forms', save_file='output.json',
                 ua_status=False, headers=None, cookies=None, timeout=10, SSL=True, proxies=None,
                 interval=0, continue_=False, try_requests=1, verbose=True):

        self.target = utils.normalize_url(target, SSL)
        self.wordlist_file = wordlist_file
        self.option = option
        self.save_file = save_file if save_file.endswith('.json') else f'{save_file.rsplit(".", 1)[0]}.json'
        self.ua_status = ua_status
        self.headers = headers
        self.cookies = cookies
        self.timeout = timeout
        self.SSL = SSL
        self.proxies = proxies
        self.interval = interval
        self.continue_ = continue_
        self.try_requests = try_requests
        self.verbose = verbose

    
    # payload   -> carga enviada
    # response  -> resposta bruta da requisicao
    async def detect_reflected_xss(self, payload, response):
        details = {
            'xss_reflected_script': False,
            'xss_reflected_attr': False,
            'xss_reflected_html': False,
        }

        soup = BeautifulSoup(response.content, 'html.parser')
        unescaped_html = html.unescape(response.text)

        for param in payload:
            for script in soup.find_all('script'):
                if script.string and param in script.string:
                    details['xss_reflected_script'] = True
                    break

            for tag in soup.find_all():
                for attr, value in tag.attrs.items():
                    value = ' '.join(value) if isinstance(value, list) else str(value)
                    if param in value or attr.lower().startswith('on') and param in tag.attrs.get(attr, ''):
                        details['xss_reflected_attr'] = True

            if param in unescaped_html:
                details['xss_reflected_html'] = True

        # BANNER CAPTURE
        banner = response.text if response.status_code in [301, 302, 307] else response.text[:500] # recolhe amostra do http
        
        return details, banner

    
    # ENGINE
    # 
    async def engine(self, payload, url, method='GET', params=None, headers=None):
        
        await asyncio.sleep(self.interval)

        print(f'[+][{utils.time_now()}] Tentando: {url}')
        
        # REQUISICAO
        status, r = Request(url, timeout=self.timeout, SSL=self.SSL, method=method, params=params,
                                    proxies=self.proxies, headers=headers or self.headers,
                                    cookies=self.cookies, ua_status=self.ua_status, redirect=False,
                                    try_requests=self.try_requests).request()
        
        if self.verbose:
            print(f'{" "*3}[>][{utils.time_now()}] Payload: {payload}')
        
        if status:
            # ANALYSIS RESPONSE
            details, banner = await self.detect_reflected_xss([payload], r)
            if any(details.values()) and not self.continue_:
                print(f'[#][{utils.time_now()}][{r.status_code}] Possível vulnerabilidade: {url} ← {payload}')
        
        else:
            print(f'{" "*3}[>][{utils.time_now()}] Falha ao requisitar: {r}')
            details, banner = {}, ''
        
        # LOG
        json_obj = jsonlog.ObjectJsonCommon.from_data(
            domain=self.target, payload=payload, url=url,
            ip='', r=r, banner=banner, details=details,
        )
        await jsonlog.AsyncLogger(self.save_file).json_write(json_obj)
        return details, banner
    
    # RUN
    async def run(self):
        
        # CARGA PESADA
        wordlist_file = self.wordlist_file
        if wordlist_file is None:
            print(f'[#][{utils.time_now()}] Usando payloads padrao')
            wordlist_file = 'wordlists/sqli/default_payload.txt'

        status_payload, payloads = await utils.fileReader(wordlist_file)
        if not status_payload:
            print(f'[-][{utils.time_now()}] {payloads}')
            return False, payloads
        
        payloads = [p.strip() for p in payloads if p.strip()]
        
        # QUERY STRING
        if self.option == 'query-string':
            if '*' not in self.target:
                return False, f'[#][{utils.time_now()}] Esperado caractere * para substituição no URL.'
            for payload in payloads:
                await self.engine(payload, self.target.replace('*', payload))
            return True, f'[#][{utils.time_now()}] Finalizado com {self.wordlist_file} → {self.save_file}'
        
        # HEADERS
        if self.option == 'headers':
            total_combinations = len(payloads) ** 3
            used_combinations = set()
            while len(used_combinations) < total_combinations:
                headers = {
                    'User-Agent': random.choice(payloads),
                    'Referer': random.choice(payloads),
                    'X-Forwarded-For': random.choice(payloads)
                }
                combo_key = frozenset(headers.items())
                if combo_key in used_combinations:
                    continue
                used_combinations.add(combo_key)
                await self.engine(f"H:{headers}", self.target, headers=headers)
            return True, f'[#][{utils.time_now()}] Finalizado com {self.wordlist_file} → {self.save_file}'

        # FORMS
        if self.option == 'forms':
            method = 'GET'
            status_forms, forms = await HTMLAnalitcs.get_all_forms(self.target)
            if not status_forms or not forms:
                return False, f'[#][{utils.time_now()}] Nenhum formulário encontrado.'
            for payload in payloads:
                for form in forms:
                    form_details = await HTMLAnalitcs.get_form_details(form, payload)
                    action = form_details['action']
                    url = utils.merge_url(self.target, action) if action else self.target
                    method = form_details['method'].upper()
                    params = {inp['name']: inp['value'] for inp in form_details['inputs']}
                    await self.engine(payload, url, method=method, params=params)
            return True, f'[#][{utils.time_now()}] Finalizado com {self.wordlist_file} → {self.save_file}'

        
        else:
            print(f'[#][{utils.time_now()}] Opcao informada inexistente')
            return False, f'[#][{utils.time_now()}] Opcao informada inexistente'


# MAIN
async def main():
    scanner = XSS(
        target='https://www.socasadas.com/?s=*',
        wordlist_file='wordlists/xss/default.txt',
        option='forms',
        save_file='xss_result.json',
        verbose=True
    )
    status, result = await scanner.run()
    print(result)


if __name__ == '__main__':
    asyncio.run(main())

