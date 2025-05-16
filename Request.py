import requests
import useragent

# timeout -> tempo maximo aguardando resposta
# ssl -> se https
# method -> metodo de requisicao 
# payload -> carga util
# ua_status -> se true, usa headers aleatorios, se houve algo em header, header sera ignorado.
# redirect -> permite o redirecionamento
# try_requests -> numero maximo de tentativas
class Request:
    def __init__(self, url, timeout=10, SSL=True, method='GET', params=None, proxies=None, headers=None, cookies=None, ua_status=False, redirect=False, try_requests=1):
        self.SSL = SSL
        self.url = self.security_protocol(url)
        self.timeout = timeout
        self.method = method
        self.params = params
        self.proxies = proxies
        self.headers = headers
        self.cookies = cookies
        self.ua_status = ua_status
        self.redirect = redirect
        self.try_requests = try_requests
    
    def security_protocol(self, url):
        if not url.startswith('http://') and not url.startswith('https://'):
            return f'https://{url}' if self.SSL else f'http://{url}'
        return url
    
    def useragent(self):
        ua = useragent
        if self.ua_status:
            return {'User-Agent': ua.get_useragent_experimental()}
        elif not self.ua_status and not self.headers:
            return {'User-Agent': ua.get_useragent_experimental()}
        else:
            return self.headers
    
    def request(self):
        while self.try_requests > 0:
            try:
                url = self.url
                if self.method == 'GET' or self.method == None:
                    
                    r = requests.get(
                        url,
                        params=self.params,
                        headers=self.useragent(),
                        cookies=self.cookies,
                        timeout=self.timeout,
                        verify=self.SSL,
                        allow_redirects=self.redirect,
                        proxies=self.proxies,
                    )
                if self.method == 'POST':
                    r = requests.post(
                        url,
                        data=self.params,
                        headers=self.headers,
                        cookies=self.cookies,
                        timeout=self.timeout,
                        verify=self.SSL,
                        allow_redirects=self.redirect,
                        proxies=self.proxies,
                    )
                return True, r
            except requests.exceptions.Timeout:
                error_msg = f'Tempo limite de requisição atingido: {url} t={self.timeout}s'
            except requests.exceptions.ConnectionError as err:
                error_msg = f'Erro de conexão: {url} - {err}'
            except requests.exceptions.RequestException as err:
                error_msg = f'Erro de requisição: {url} - {err}'
            except requests.exceptions.SSLError as err:
                error_msg = f'Erro de certificado: {url} - {err}'
            except Exception as err:
                error_msg = f'Erro nao documentado encontrado: {url} - {err}'
            self.try_requests -= 1
        return False, error_msg


# Exemplo de uso
# print(Request('google.com').request())