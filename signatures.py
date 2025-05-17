import re

# Mensagens de erro por tipo de bds
SQLI_ERRORS = {
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

# Tipos de bds para verificacao do headers
DATABASE_HEADERS = [
    'mysql', 'postgresql', 'sqlserver', 'oracle', 'mongodb',
    'sqlite', 'redis', 'db2', 'mariadb', 'cockroachdb'
]

# WAF - servidores conhecidos
WAF_SERVERS = [
    'cloudflare', 'sucuri', 'akamai', 'imperva', 'incapsula', 'barracuda',
    'f5 big-ip', 'aws', 'amazon cloudfront', 'fastly', 'edgecast', 'stackpath',
    'radware', 'druva', 'nsfocus', 'fortinet', 'fortiweb', 'citrix', 'cdn77',
    'qualys', 'netscaler', 'bluedon', 'dotdefender', 'alert logic', 'trustwave',
    'denyall', 'oracle cloud', 'shield square', 'reblaze', 'akamai ghost',
    'wangsu', 'yundun', 'baidu yunjiasu', 'aliyun', '360 web application firewall',
    'tencent cloud',
]

# WAF - códigos de status suspeitos
WAF_STATUS_CODES = [
    400, 401, 403, 404, 406, 408, 409, 411, 413, 414, 418, 429, 451
]

# WAF - padrões de redirecionamento comuns
WAF_REDIRECT_PATHS = [
    '/error', '/security-check', '/blocked'
]

# WAF - frases indicativas de bloqueio
WAF_BLOCK_PHRASES = [
    'access denied', 'request blocked', 'forbidden', 'not allowed',
    'waf', 'web application firewall', 'security check', 'malicious request',
    'you have been blocked', 'denied by policy'
]

# WAF - headers comuns
WAF_HEADERS = [
    'x-sucuri-id', 'cf-ray', 'x-akamai-transformed', 'x-cdn'
]