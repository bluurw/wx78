import asyncio
import random
import re

import utils
import jsonlog
import commons


# payload -> carga enviada
# response -> resposta bruta da requisicao 
async def sqli_score_system(payload, response):
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


# response -> resposta bruta da requisicao
async def waf_detection(response):
    score = 0
    waf_servers = [
        'cloudflare', 'sucuri', 'akamai', 'imperva', 'incapsula', 'barracuda',
        'f5 big-ip', 'aws', 'amazon cloudfront', 'fastly', 'edgecast', 'stackpath',
        'radware', 'druva', 'nsfocus', 'fortinet', 'fortiweb', 'citrix', 'cdn77',
        'qualys', 'netscaler', 'bluedon', 'dotdefender', 'alert logic', 'trustwave',
        'denyall', 'oracle cloud', 'shield square', 'reblaze', 'akamai ghost',
        'wangsu', 'yundun', 'baidu yunjiasu', 'aliyun', '360 web application firewall',
        'tencent cloud',
    ]
    waf_status_code = [400, 401, 403, 404, 406, 408, 409, 411, 413, 414, 418, 429, 451]
    waf_redirect = ['/error', '/security-check', '/blocked']
    waf_block_phrases = [
        'access denied', 'request blocked', 'forbidden', 'not allowed',
        'waf', 'web application firewall', 'security check', 'malicious request',
        'you have been blocked', 'denied by policy',
    ]
    waf_headers = ['x-sucuri-id', 'cf-ray', 'x-akamai-transformed', 'x-cdn']

    responder_headers = [k.lower() for k in response.headers.keys()]
    
    waf_possibility = {
        'servers': 10 if response.headers.get('server', '').lower() in waf_servers else 0,
        'status_code': 3 if response.status_code in waf_status_code else 0,
        'location': 10 if response.headers.get('location', '').lower() in waf_redirect else 0,
        'block_pharses': 5 if any(pharses.lower() in response.text.lower() for pharses in waf_block_phrases) else 0,
        'headers': 5 if any(term.lower() in responder_headers for term in waf_block_phrases) else 0,
    }
    score += sum(v for v in waf_possibility.values())
    return True if score >= 10 else False

# target -> origem
# payload -> carga enviada
# response -> resposta bruta da request
# score_sqli -> score que atesta vulnerabilidade
# continue_ -> valor booleano que decide se continua ou nao apos encontrar vulnerabilidade
async def response_analyzer(target, payload, response, score_sqli):
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

    if score_sqli:
        score = await sqli_score_system(payload, response)
        details['sqli_score'] = score

    for k, v in error_messages.items(): # itera sobre o dicionario
        # if any(re.search(error_msg.lower(), response.text.lower()) for error_msg in v): # verifica o tipo de erro no retorno
        for error_msg in v:
            if re.search(error_msg.lower(), response.text.lower(), re.IGNORECASE | re.DOTALL):
                details['database_type'] = k
                details['work_sqli'] = True
                
                print(f'{" "*3}[>][{commons.time_now()}][{response.status_code}] Possivel vulnerabilidade: {target} -> {payload}')
                print(f'{" "*3}[>] Tipo: {k} Msg: {error_msg} url: {response.url} Score: {score}')
            else:
                details['work_sqli'] = False
    details['waf'] = await waf_detection(response) # verifica a chance de ter waf
    banner = response.text if response.status_code in [301, 302, 307] else response.text[:500] # recolhe amostra do http

    return details, score, banner


async def sqli(target, wordlist_file, option, save_file, ua_status, headers, cookies, timeout, SSL, proxies, interval, continue_, score_sqli, try_requests, verbose):
    #scheme = 'https' if SSL else 'http'
    save_file = save_file if save_file.endswith('.json') else f'{save_file.rsplit(".", 1)[0]}.json'
    if wordlist_file is None:
        print(f'[#][{commons.time_now()}] Usando payloads padrao')
        wordlist_file = 'wordlists/sqli/default_payload.txt'

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
            details, score, banner = await response_analyzer(target, payload, r, score_sqli=score_sqli)
            if details['work_sqli'] and not continue_:
                print(f'[#][{commons.time_now()}][{response.status_code}] Possivel vulnerabilidade: {target} -> {payload}')
                return details, score, banner
        else:
            print(f'{" "*3}[>][{commons.time_now()}] Falha ao requisitar: {r}')
            details, score, banner = {}, 0, ''
        
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
            combo_key = frozenset(current_headers.items())
            if combo_key in used_combinations:
                continue

            used_combinations.add(combo_key)
            url = f"{target.split('://')[0]}://{target.split('://')[1]}" if target.startswith('http://') or target.startswith('https://') else f'https://{target}' if SSL else f'http://{target}'  # aqui o payload está no header, não na URL
            await engine(f'UA:{current_headers["User-Agent"]}|Ref:{current_headers["Referer"]}|IP:{current_headers["X-Forwarded-For"]}', url, headers=current_headers)

        return True, f'[#][{commons.time_now()}] Wordlist concluida: {wordlist_file} → {save_file}'

    else:
        return False, f'[-][{commons.time_now()}] Opcao invalida: {option}'


# Attack
async def main(target, wordlist_file='wordlists/sqli/default_payload.txt', option='query string', save_file='sqli_test.json', ua_status=False, headers=None, cookies=None, timeout=10, SSL=True, proxies=None, interval=0, continue_=False, score_sqli=False, try_requests=1, verbose=True):
    try:
        status, attk = await sqli(target, wordlist_file, option, save_file, ua_status, headers, cookies, timeout, SSL, proxies, interval, continue_, score_sqli, try_requests, verbose)
        if status:
            return True, f'[#] Execucao finalizada: {attk}'
        else:
            return False, f'[#] Execucao finalizada: {attk}'
    except TypeError:
        return False, f'[#] Um erro de tipagem surgiu'
    except Exception as err:
        return False, f'[#] Um erro surgiu & a execucao foi interrompida {err}'