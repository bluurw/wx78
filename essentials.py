import json

def fileReader(file):
    try:
        with open(f'{file}', 'r') as f:
            lines = f.readlines()
            return lines
    except FileNotFoundError:
        return False
    
# Json para geracao de logs
def json_write(log, file='log.json'):
    try:
        with open(file, "r", encoding="utf-8") as f:
            json_load = json.load(f)
        if isinstance(json_load, list): # verifica se os dados passados sao listas
            json_load.append(log)
        else:
            json_load = [json_load, log]
        with open(file, 'w', encoding='utf-8') as f: # sobrescreve arquivo
            json.dump(json_load, f, indent=4, ensure_ascii=False)
        return True, 'Sucesso ao escrever arquivo'    
    except FileNotFoundError:
        with open(file, "w", encoding="utf-8") as f:
            json.dump([log], f, indent=4, ensure_ascii=False)
        return True, 'Sucesso ao escrever arquivo'
    except Exception as e:
        return False, f'Erro ao escrever arquivo {e}'