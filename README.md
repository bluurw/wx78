[![License](https://img.shields.io/badge/license-MIT-_red.svg)](https://opensource.org/licenses/MIT)
[![Contribuitions Welcome](https://img.shields.io/badge/contribuitions-welcome-brightgreen.svg?style=flat)](https://github.com/bluurw/wx78/issues)

# **Proxy**

## **Descrição**

WX78 busca identificar e explorar uma gama de vulnerabilidades em aplicacoes web, que vao desde missconfigurations a vulnerabilidades comuns (xss, sqli, idor, entre outras), ate vulnerabilidades avancadas. Apos feita esta analise e gerado um arquivo .json que pode ser usado em relatorios.

## **Como Instalar**

Siga os passos abaixo para instalar e executar o projeto:

Clone o repositório
```bash
git clone https://github.com/bluurw/wx78.git
```

Entre na pasta do projeto
```bash
cd wx78
```

Crie um ambiente virtual (opcional, mas recomendado)
```bash
python3 -m venv wx78
source venv/bin/activate
```

Instale as dependências
```bash
pip install -r requirements.txt
```

Execute o código principal
```bash
python main.py
```

## **TO DO**

- Concilar todos em um main
- Desenvolver a interface web que utilize o .json

## **Compatibilidade**
- Linux: OK
- Windows: Não testado
- Mac: Não testado

## **Licença**

Este projeto é licenciado sob a Licenca do MIT.