from dataclasses import dataclass, asdict
from typing import Optional, Dict, List
import aiofiles
import asyncio
import json
import shutil

import commons

@dataclass
class ObjectJsonWhois:
    domain_name: Optional[str] = None
    registrar: Optional[str] = None
    whois_server: Optional[str] = None
    referral_url: Optional[str] = None
    update_date: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    status: Optional[List[str]] = None
    name_servers: Optional[List[str]] = None
    registrant: Optional[dict] = None
    administrative_contact: Optional[dict] = None
    technical_contact: Optional[dict] = None
    billing_contact: Optional[dict] = None
    dnssec: Optional[dict] = None

    def to_dict(self):
        return asdict(self)
    
    @staticmethod
    def from_data(response_whois):
        return ObjectJsonWhois(
            domain_name=response_whois.get('domain_name') or response_whois.get('domain'),
            registrar=response_whois.get('registrar'),
            whois_server=response_whois.get('whois_server'),
            referral_url=response_whois.get('referral_url'),
            update_date=response_whois.get('update_date') or response_whois.get('updated_date'),
            creation_date=response_whois.get('creation_date'),
            expiration_date=response_whois.get('expiration_date') or response_whois.get('expires_date'),
            status=response_whois.get('status'),
            name_servers=response_whois.get('name_servers') or response_whois.get('nameservers'),
            registrant=response_whois.get('registrant'),
            administrative_contact=response_whois.get('admin'),
            technical_contact=response_whois.get('tech'),
            billing_contact=response_whois.get('billing'),
            dnssec=response_whois.get('dnssec')
        )


@dataclass
class ObjectJsonCommon:
    domain: str
    ip: str
    payload: dict
    url: str
    status_code: int
    response_time: float
    error: bool
    error_details: str
    date_time: str
    details: Optional[dict]
    redirect_history: List[str]
    response_certificate: Optional[dict]
    response_headers: Optional[dict]
    banner: Optional[str]

    def to_dict(self):
        return asdict(self)
    
    @staticmethod
    def from_data(domain, payload, url, ip, r, details={}, cert_metadata={}, banner=None):
        status = True if 'requests.models.Response' in str(type(r)) else False
        return ObjectJsonCommon(
            domain=domain,
            ip=ip,
            payload=payload,
            url=url,
            status_code=r.status_code if status else 404,
            response_time= r.elapsed.total_seconds() if status else None,
            error=status,
            error_details=None if status else r,
            date_time=commons.time_now(),
            details=details,
            redirect_history=[resp for resp in r.history if resp.status_code in [301, 302, 307]] if status else [],
            response_certificate=cert_metadata,
            response_headers=dict(r.headers) if status else {},
            banner=banner,
        )


class AsyncLogger:
    def __init__(self, file='log.json'):
        self.file = file

    async def json_write(self, log_):
        file = self.file
        
        # serializa o objeto
        def serialize(obj):
            if hasattr(obj, '__dict__'):
                return obj.__dict__
            return obj
        try:
            temp_file = f"{file}.tmp" # cria um arquivo temporario
            async with aiofiles.open(temp_file, 'w', encoding='utf-8') as f:
                try:
                    async with aiofiles.open(file, 'r', encoding='utf-8') as original:
                        content = await original.read()
                        logs = json.loads(content) if content else []
                except FileNotFoundError:
                    logs = []
                
                logs.append(serialize(log_))
                await f.write(json.dumps(logs, indent=4, ensure_ascii=False, default=str))
            
            shutil.move(temp_file, file)
            return True, 'Log escrito com sucesso'
        except Exception as err:
            return False, f'Erro ao escrever arquivo: {err}'



# descontinuado
'''
class AsyncLogger:
    def __init__(self, file='log.json'):
        self.file = file

    async def json_write(self, log_: 'ObjectJson'):
        file = self.file
        log = log_.to_dict()
        try:
            async with aiofiles.open(file, 'a', encoding='utf-8') as f:
                json_line = json.dumps(log, ensure_ascii=False)
                await f.write(json_line + '\n')
            return True, 'Log escrito com sucesso'
        except Exception as err:
            return False, f'Erro ao escrever arquivo: {err}'
'''