import asyncio

import utils
import jsonlog
import certificate
import HTMLAnalitcs
import supplementary
from Request import Request


class Subdomain:
    def __init__(self, target, wordlist_file='wordlists/subdomain/wordlist.txt', filter_status_code=[], option='query-string', 
                 save_file='output.json', ua_status=False, headers=None, cookies=None, timeout=10, SSL=True, redirect=False, proxies=None,
                 interval=0, continue_=False, try_requests=1, verbose=True, advanced=False):

        self.target = utils.normalize_url(target, SSL)
        self.wordlist_file = wordlist_file
        self.filter_status_code = filter_status_code
        self.option = option
        self.save_file = save_file if save_file.endswith('.json') else f'{save_file.rsplit(".", 1)[0]}.json'
        self.ua_status = ua_status
        self.headers = headers
        self.cookies = cookies
        self.timeout = timeout
        self.SSL = SSL
        self.redirect = redirect
        self.proxies = proxies
        self.interval = interval
        self.continue_ = continue_
        self.try_requests = try_requests
        self.verbose = verbose
        self.advanced = advanced
    

    # ENGINE
    # 
    async def engine(self, url, payload, method='GET', params=None, headers=None):

        ip = ''
        banner = ''
        details = {}
        cert_metadata = {}

        await asyncio.sleep(self.interval)

        if self.verbose:
            print(f'[+][{utils.time_now()}] Testando: {url}')
            
        status, r = Request(url, timeout=self.timeout, SSL=self.SSL, method=method, params=params,
                            proxies=self.proxies, headers=headers or self.headers,
                            cookies=self.cookies, ua_status=self.ua_status, redirect=self.redirect,
                            try_requests=self.try_requests).request()
        
        if status:
            if (len(self.filter_status_code) == 0 and self.verbose) or (len(self.filter_status_code) != 0 and r.status_code in self.filter_status_code):
                print(f'{" "*3}[>][{utils.time_now()}][{r.status_code}] {url}')
            
            if self.advanced:
                # CERTIFICATE
                cert_metadata = await certificate.certificate_vulnerability(url.split('://')[1])    # CERTIFICADO
                
                banner = r.text if r.status_code in [301, 302, 307] else r.text[:500]   # BANNER
                redirect_history = [resp for resp in r.history if resp.status_code in [301, 302, 307]]  # HISOTRICO

                # WAF
                details['waf'] = await supplementary.test_waf_detection(r) # verifica a chance de ter waf

                # INFO
                details['urls'] = HTMLAnalitcs.get_all_url(r)
                details['paths'] = HTMLAnalitcs.get_all_path(r)
                details['emails'] = HTMLAnalitcs.get_all_emails(r)
                details['telephone'] = HTMLAnalitcs.get_all_telephones(r)
                
                # IP
                status_ip, ip = supplementary.get_ip_host(url)
            
        else:
            if len(self.filter_status_code) == 0 or (len(self.filter_status_code) != 0 and 404 in self.filter_status_code):
                print(f'{" "*3}[>][{utils.time_now()}][404] {url}: {r}')
        
        # LOG
        json_obj = jsonlog.ObjectJsonCommon.from_data(
            domain=self.target, payload=payload, url=url, ip=ip, r=r, 
            cert_metadata=cert_metadata, banner=banner, details=details
        )
        await jsonlog.AsyncLogger(self.save_file).json_write(json_obj)
    

    async def run(self):

        # CARGA PESADA
        wordlist_file = self.wordlist_file
        if wordlist_file is None:
            print(f'[#][{utils.time_now()}] Usando payloads padrao')
            wordlist_file = 'wordlists/subdomain/wordlist.txt'

        status_payload, payloads = await utils.fileReader(wordlist_file)
        if not status_payload:
            print(f'[-][{utils.time_now()}] {payloads}')
            return False, payloads
        
        payloads = [p.strip() for p in payloads if p.strip()]


        # QUERY STRING
        if self.option == 'query-string':
            for payload in payloads:
                test_url = f'{self.target.split("://")[0]}://{payload}.{self.target.split("://")[1]}' if self.target.startswith('https://') or self.target.startswith('http://') else f'https://{payload}.{self.target}'
                start_engine = await self.engine(test_url, payload)
            return True, f'[#][{utils.time_now()}] Finalizado com {self.wordlist_file} → {self.save_file}'
        
        else:
            print(f'[#][{utils.time_now()}] Opcao informada inexistente')
            return False, f'[#][{utils.time_now()}] Opcao informada inexistente'


# MAIN
async def main(target, wordlist_file='wordlists/subdomain/wordlist.txt', filter_status_code=[], option='query-string', 
                save_file='output.json', ua_status=False, headers=None, cookies=None, timeout=10, SSL=True, redirect=False,
                proxies=None, interval=0, continue_=False, try_requests=1, verbose=True, advanced=False):
    
    scanner = Subdomain(target, wordlist_file, filter_status_code, option, save_file, ua_status, headers, 
                        cookies, timeout, SSL, redirect, proxies, interval, continue_, try_requests, verbose, advanced
                        )
    status, result = await scanner.run()