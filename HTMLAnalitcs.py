import re
from bs4 import BeautifulSoup

from Request import Request

# target    -> alvo
async def get_all_forms(target):
    status, r = Request(target).request()
    if status:
        soup = BeautifulSoup(r.text, 'html.parser')
        return True, soup.find_all('form')
    return False, 'Falha na requisição'


# form      -> formularios encontrados
# payload   -> carga
async def get_form_details(form, payload):
    action = form.get('action')
    method = form.get('method', 'get').lower()
    inputs = []
    for input_tag in form.find_all('input'):
        name = input_tag.get('name')
        if name:
            inputs.append({'type': input_tag.get('type', 'text'), 'name': name, 'value': payload})
    return {'action': action, 'method': method, 'inputs': inputs}


# response -> bruto text da requisicao
# coleta telefones
def get_all_telephones(response):
    set_ = set()
    rgx = r'^\+?\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{4,10}'
    for result in re.findall(rgx, response.text, re.DOTALL):
        set_.add(result)
    return set_


# coleta emails
def get_all_emails(response):
    set_ = set()
    rgx = r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+'
    for result in re.findall(rgx, response.text, re.DOTALL):
        set_.add(result)
    return set_


# input
def get_all_input(response):
    set_ = set()
    rgx = r'<input\b[^>]*>'
    for result in re.findall(rgx, response.text, re.DOTALL):
        set_.add(result)
    return set_


# meta
def get_all_meta(response):
    meta_set = set()
    rgx = r'<meta\b[^>]*>'
    for result in re.findall(rgx, response.text, re.DOTALL):
        meta_set.add(result)
    return meta_set


# urls
def get_all_url(response):
    urls = set()
    rgx = r'https?://[^\s"\'<>(){}\[\]]+'
    for result in re.findall(rgx, response.text, re.DOTALL):
        urls.add(result)
    return urls


# paths
def get_all_path(response):
    urls = set()
    rgx = r'href\s*=\s*(?:"([^"]+)"|\'([^\']+)\'|([^>\s]+))'
    for result in re.findall(rgx, response.text, re.DOTALL):
        href = [link for link in result if link]
        urls.add(href[0])
    return urls


# DESCONTINUADO
# response  -> resposta bruta
'''
def get_all_form(response):
    set_ = set()
    rgx = r'<form.*?>.*?</form>'
    for result in re.findall(rgx, response.text, re.DOTALL):
        set_.add(result)
    return set_
'''

# response.headers['server']
# response.headers['content-type']
# response.heaers['x-powered-by']
# response.headers['host']
# response.headers['strict-transport-security']
# response.headers['content-encoding']