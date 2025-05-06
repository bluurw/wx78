import re

# response -> bruto text da requisicao


# coleta telefones
def get_all_telephones(response):
    set_ = set()
    rgx = re.compile(r'^\+?\d{1,3}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{4,10}')
    for result in re.findall(rgx, response.text, re.DOTALL):
        set_.add(result)
    return set_


# coleta emails
def get_all_emails(response):
    set_ = set()
    rgx = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]')
    for result in re.findall(rgx, response.text, re.DOTALL):
        set_.add(result)
    return set_


# form
def get_all_form(response):
    set_ = set()
    rgx = r'<form.*?>.*?</form>'
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


# response.headers['server']
# response.headers['content-type']
# response.heaers['x-powered-by']
# response.headers['host']
# response.headers['strict-transport-security']
# response.headers['content-encoding']