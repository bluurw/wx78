import asyncio

import ssl
import socket
from datetime import datetime as dt
from cryptography import x509
from cryptography.hazmat.backends import default_backend

import functions

# requisita o certificado da pagina
async def get_ssl_info(hostname, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return True, {
                    'subject': cert.get('subject', 'Unknow'),
                    'issuer': cert.get('issuer', 'Unknow'),
                    'version': cert.get('version', 'Unknow'),
                    'serialNumber': cert.get('serialNumber', 'Unknow'),
                    'notBefore': cert.get('notBefore', 'Unknow'),
                    'notAfter': cert.get('notAfter', 'Unknow'),
                    'OCSP': cert.get('OCSP', 'Unknow'),
                    'CRLDistributionPoints': cert.get('crlDistributionPoints', 'Unknow'),
                }
    except Exception as e:
        return False, f'Erro ao obter o certificado: {e}'

# apresenta de maneira legivel o certificado
async def certificate(hostname):
    status, certificate = get_ssl_info(hostname)
    if isinstance(certificate, dict): # verifica se realmente e um dict
        print('Informações do certificado:')
        for key, value in certificate.items():
            print(f'{key}: {value}')
    else:
        print(certificate)

# Exemplo de uso
# certificate('example.com')

# valida a integridade do certificado
async def check_revoked(serial):
    status, r = await functions.request(
        'http://crl3.digicert.com/DigiCertGlobalG3TLSECCSHA3842020CA1-2.crl', # bd certificados
        timeout = None,
        SSL = False,
        ) 
    if status:
        crl = x509.load_der_x509_crl(r.content, default_backend())
        revogado = any(entry.serial_number == int(serial, 16) for entry in crl)
    
        if revogado:
            return True, 'certificado revogado'
        else:
            return True, 'certificado válido'
    else:
        return False, f'Erro ao acessar a CRL: {response.status_code}'

# testa possiveis vulnerabilidades
async def certificate_vulnerability(hostname):
    vulnerabilities_certificate = {}

    status, certificate = await get_ssl_info(hostname)
    
    if status:
        # Testa confiabilidade do certificado
        test_url = f'https://{hostname}:443'
        status, r = await functions.request(test_url, timeout=10, SSL=True) # faz a validacao do cerificado
        # se retornar True, nao tem vulnerabilidade
        vulnerabilities_certificate['trusted_certificate'] = True if status else False

        # Testa data de validade do certificado
        date_format = "%b %d %H:%M:%S %Y %Z" # formato data/hora da string
        date_object = dt.strptime(certificate['notAfter'], date_format)
        current_time = dt.now()
        vulnerabilities_certificate['expired_certificate'] = (True, str(date_object)) if current_time > date_object else (False, str(date_object))

        # Testa a integridade do certificado
        status, check_integrity = await check_revoked(certificate['serialNumber'])
        if status:
            if 'válido' in check_integrity:
                vulnerabilities_certificate['revoked'] = False
            else:
                vulnerabilities_certificate['revoked'] = True
        else: # se retornar erro
            vulnerabilities_certificate['revoked'] = False
    
    return vulnerabilities_certificate

# Exemplo de uso
# print(certificate_vulnerability('example.com'))


