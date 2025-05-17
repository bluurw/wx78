import asyncio
import aiofiles
from urllib.parse import urljoin
from datetime import datetime as dt


def time_now():
    return dt.now().strftime('%d/%m/%Y %H:%M:%S') # hora atual


# le wordlists
# file -> caminho do arquivo
async def fileReader(file):
    try:
        async with aiofiles.open(f'{file}', 'r') as f:
            lines = await f.readlines()
            return True, lines
    except FileNotFoundError:
        return False, 'Arquivo nao encontrado'
    except Exception as err:
        return False, err



# url -> url original
# outstreched -> caminho, acao, etc
def merge_url(url, outstreched):
    return urljoin(url, outstreched)



def normalize_url(target, SSL):
        if target.startswith(('http://', 'https://')):
            return target
        return f'https://{target}' if SSL else f'http://{target}'
