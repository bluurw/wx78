import asyncio
import aiofiles

import json

# le wordlists
# file -> caminho do arquivo
async def fileReader(file):
    try:
        async with aiofiles.open(f'{file}', 'r') as f:
            lines = await f.readlines()
            return lines
    except FileNotFoundError:
        return False
    
# escreve o log
# log -> param em formato a ser escrito
# file -> caminho do arquivo
async def json_write(log, file='log.json'):
    await asyncio.sleep(0.1)  # Pausa entre as chamadas
    try:
        async with aiofiles.open(file, 'r', encoding='utf-8') as f:
            content = await f.read()  # le o conteudo como texto
            json_load = json.loads(content) if content else []  # converte para json
        if isinstance(json_load, list): # se json for lista
            json_load.append(log)
        else:
            json_load = [json_load, log] # transforma em lista
        async with aiofiles.open(file, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(json_load, indent=4, ensure_ascii=False))

        return True, 'Sucesso ao escrever arquivo'
    except FileNotFoundError: # se o arquivo ainda nao existe
        async with aiofiles.open(file, 'w', encoding='utf-8') as f:
            await f.write(json.dumps([log], indent=4, ensure_ascii=False))

        return True, 'Sucesso ao escrever arquivo'
    except Exception as e:
        return False, f'Erro ao escrever arquivo: {e}'