import asyncio

import utils
import jsonlog
import certificate
import HTMLAnalitcs
import supplementary
from Request import Request


class Subdirectory:
    def __init__(self, target, wordlist_file='wordlists/subdirectory/wordlist.txt', filter_status_code=[], option='query-string', 
                 save_file='output.json', ua_status=False, headers=None, cookies=None, timeout=10, SSL=True, proxies=None,
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
        self.proxies = proxies
        self.interval = interval
        self.continue_ = continue_
        self.try_requests = try_requests
        self.verbose = verbose
        self.advanced = advanced
    

    # ENGINE
    # 
    async def engine(self, payload, url, method='GET', params=None, headers=None):

        ip = ''
        banner = ''
        details = {}

        await asyncio.sleep(self.interval)

        if self.verbose:
            print(f'[+][{utils.time_now()}] Testando: {url}')
            
        status, r = Request(url, timeout=self.timeout, SSL=self.SSL, method=method, params=params,
                            proxies=self.proxies, headers=headers or self.headers,
                            cookies=self.cookies, ua_status=self.ua_status, redirect=False,
                            try_requests=self.try_requests).request()
        
        if status:
            if len(self.filter_status_code) == 0 or (len(self.filter_status_code) != 0 and r.status_code in self.filter_status_code):
                print(f'{" "*3}[>][{utils.time_now()}][{r.status_code}] {url}')
            
            if self.advanced:
                cert_metadata = await certificate.certificate_vulnerability(url)    # CERTIFICADO
                banner = r.text if r.status_code in [301, 302, 307] else r.text[:500]   # BANNER
                redirect_history = [resp for resp in r.history if resp.status_code in [301, 302, 307]]  # HISOTRICO

                # INFO ADICIONAL DA PAGINA
                details['urls'] = HTMLAnalitcs.get_all_url(r)
                details['paths'] = HTMLAnalitcs.get_all_path(r)
                details['emails'] = HTMLAnalitcs.get_all_emails(r)
                details['telephone'] = HTMLAnalitcs.get_all_telephones(r)
                
                # COLETA IP
                status_ip, ip = supplementary.get_ip_host("".join(url[1:]))
            
        else:
            if len(self.filter_status_code) == 0 or (len(self.filter_status_code) != 0 and 404 in self.filter_status_code):
                print(f'{" "*3}[>][{utils.time_now()}][404] {url}: {r}')
        
        # LOG
        json_obj = jsonlog.ObjectJsonCommon.from_data(
            domain=self.target, payload=payload, url=url,
            ip=ip, r=r, banner=banner, details=details
        )
        await jsonlog.AsyncLogger(self.save_file).json_write(json_obj)
    

    async def run(self):

        # CARGA PESADA
        wordlist_file = self.wordlist_file
        if wordlist_file is None:
            print(f'[#][{utils.time_now()}] Usando payloads padrao')
            wordlist_file = 'wordlists/sqli/default_payload.txt'

        status_payload, payloads = await utils.fileReader(wordlist_file)
        if not status_payload:
            print(f'[-][{utils.time_now()}] {payloads}')
            return False, payloads
        
        payloads = [p.strip() for p in payloads if p.strip()]


        # QUERY STRING
        if self.option == 'query-string':
            for payload in payloads:
                url = utils.merge_url(self.target, payload)
                start_engine = await self.engine(payload, url)
            
            return True, f'[#][{utils.time_now()}] Finalizado com {self.wordlist_file} → {self.save_file}'
        
        else:
            print(f'[#][{utils.time_now()}] Opcao informada inexistente')
            return False, f'[#][{utils.time_now()}] Opcao informada inexistente'




# MAIN
async def main():
    scanner = Subdirectory(
        target='https://www.socasadas.com/',
        wordlist_file='wordlists/subdirectory/wordlist.txt',
        filter_status_code=[200, 301],
        option='query-string',
        save_file='subdir.json',
        SSL=True,
        verbose=True,
        advanced=True,
    )
    status, result = await scanner.run()


if __name__ == '__main__':
    asyncio.run(main())