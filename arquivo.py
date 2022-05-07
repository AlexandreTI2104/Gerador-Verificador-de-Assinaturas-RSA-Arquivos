# Define interfaces para criar um arquivo txt usado nos contextos de criptografia.
# Funções para entrada e saída.
import json


def escrita(nome_arquivo, dados):
    with open(nome_arquivo, 'w+', encoding = 'utf-8') as f:
        f.write(dados)


def escrita_criptograma(nome_arquivo, dados_encriptados: dict, modo = 'w'):
    with open(nome_arquivo, modo) as f:
        f.write(f'{dados_encriptados}')


def lendo_criptograma(nome_arquivo, modo = 'r'):
    data = ''

    with open(nome_arquivo, modo) as f:
        data = f.read()

    data = data.replace('\'', "\"")
    criptograma = json.loads(data)

    return criptograma


def lendo(nome_arquivo, modo = 'r'):
    with open(nome_arquivo, modo) as f:
        return f.read()


def lendo_chaves(nome_arquivo, modo = 'r'):
    data = ''

    with open(nome_arquivo, modo) as f:
        data = f.read()

    data = data.replace('\'', "\"")
    chave = json.loads(data)

    return chave


def escrevendo_chaves(nome_arquivo, chave: dict, modo = 'w'):
    with open(nome_arquivo, modo) as f:
        f.write(f'{chave}')