import re

# sondar a pagina catalogando linguagem usada (html, css, js, php) entre outras tecnologias (bancos de dados, etc)

# form
def get_all_form(r):
    set_ = set()
    rgx = r'<form.*?>.*?</form>'
    for result in re.findall(rgx, r.text, re.DOTALL):
        set_.add(result)
    return set_

# input
def get_all_input(r):
    set_ = set()
    rgx = r'<input\b[^>]*>'
    for result in re.findall(rgx, r.text, re.DOTALL):
        set_.add(result)
    return set_

# meta
def get_all_meta(r):
    meta_set = set()
    rgx = r'<meta\b[^>]*>'
    for result in re.findall(rgx, r.text, re.DOTALL):
        meta_set.add(result)
    return meta_set

# urls
def get_all_url(r):
    urls = set()
    rgx = r'https?://[^\s"\'<>(){}\[\]]+'
    for result in re.findall(rgx, r.text, re.DOTALL):
        urls.add(result)
    return urls

# paths
def get_all_path(r):
    urls = set()
    rgx = r'href\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([^>\s]+))'
    for result in re.findall(rgx, r.text, re.DOTALL):
        href = [link for link in result if link]
        urls.add(href[0])
    return urls

# r.headers['server']
# r.headers['content-type']
# r.heaers['x-powered-by']
# r.headers['host']
# r.headers['strict-transport-security']
# r.headers['content-encoding']