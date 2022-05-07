import arquivo
import random, base64, hashlib, math, string, argparse, sys
from collections import Counter
die = random.SystemRandom() # Procura um único número primo.
from random import randint as rand



tabela_primos = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 
    113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257,
    263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 
    421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509,]


def teste_primalidade(x, y):  
    is_primo = x - 1
    check = pow(y, is_primo, x)

    while not is_primo & 1:
        is_primo >>= 1

    if check == 1:
        return True

    while is_primo < x - 1:
        if check == x - 1:
            return True
        is_primo <<= 1
    return False        


def miller_rabin(x, y):

    for i in range(y):
        if (x == 2 or x == 3):
            return True
        elif (x == 1 or x == 0):
            return False
        else:   
            a = die.randrange(2, x - 1)
            if not teste_primalidade(x, a):
                return False    
    return True        
      

def geracao_dos_primos(bits):
    y = 40
    diferente = False
    
    while not diferente: # Está garantindo que "gen_prime" é ímpar.
        gen_prime = (die.randrange(1 << bits - 1, 1 << bits) << 1) + 1
        if miller_rabin(gen_prime, y):
            return gen_prime


# Geração de Chaves Simétricas AES

def geracao_chaves_simetricas(bits): # Obtendo uma geração de chaves simétricas de números aleatórios no intervalo definido.
    y = 40  
    diferente = False
    
    while not diferente: # Está garantindo que "gen_prime" é ímpar para gerar chaves simétricas.
        gen_prime = (die.randrange(1 << bits - 1, 1 << bits) << 1) + 1
        if teste_primalidade(gen_prime, y):
            return gen_prime



def coprimo(tamanho = 1024): # Gerando um coprimo candidato a primo com os primeiros primos da tabela.
    while True:
        possivel_candidato = geracao_chaves_simetricas(tamanho)
        for primo in tabela_primos:
            if possivel_candidato % primo == 0 and primo ** 2 <= possivel_candidato:
                break
            else:
                return possivel_candidato


def obter_numero_aleatorio_bits(tamanho = 1024): # Obtendo um número aleatório com um tamanho de bits o qual seja um bom candidato e passe no teste de primalidade.
    y = 40
    while True:
        possivel_candidato = coprimo(tamanho)
        if miller_rabin(possivel_candidato, y):
            return possivel_candidato


# Cifração Simétrica modo CTR

"""
def int_of_string(s):
    return int(binascii.hexlify(s), 16)

def cifracao_simetrica_aes(message, senha):
    vetor_inicializacao = random.new().read(16) # Geração do vetor de inicialização de 16 bytes
    vetor_inicializacao = os.urandom(16)
    
    ctr = Counter.new(128, initial_value=int_of_string(vetor_inicializacao))

    h = hashlib.sha256.new()  # Geração da chave de 16 bytes a partir da senha.
    h.update(geracao_chaves_simetricas(16))
    senha = h.digest()[0:16]


    message = base64.b64decode(message.encode())
    
    for i in range(16 - (len(message) % 16)): # percorrendo no tamanho da mensagem a ser cifrada
        message += " "


        return encryptor.update(message.encode("utf-8") + encryptor.finalize())
"""

# Cifração assimétrica da chave de sessão, usando OAEP.


def mdc_extensao_euclidiana(a, b): # Algoritmo de Extensão Euclidiana
  x, antigo_x = 0, 1
  y, antigo_y = 1, 0
  z, antigo_z = b, a
  
  while True: 
    if (z != 0):
      quociente = antigo_z // z
      antigo_z, z = z, antigo_z - quociente * z
      antigo_x, x = x, antigo_x - quociente * x
      antigo_y, y = y, antigo_y - quociente * y
    else: 
      break
  return antigo_z, antigo_x, antigo_y
  

def gerador_de_chaves_rsa(p, q): # Gerador de um par de chaves públicas e privadas 
    primos = p * q
    phi = (p - 1) * (q - 1)
    while not (False):
        public = random.randint(1, phi - 1)
        if math.gcd(public, phi) == 1 and public != phi: 
            x, y, z = mdc_extensao_euclidiana(phi, public)
            if x == (y * phi + z * public):
                priv = z % phi
                break

    chave_publica = {'public': public, 'n': primos}
    chave_privada = {'priv': priv, 'n': primos}

    return chave_publica, chave_privada


# Parte 02 Assinatura

def assinatura_hash(dados): # Funções de hash para ajudar na verificação de assinatura, que retorna um resumo de 32 bytes da aplicação de SHA3 256 em dados.
    return hashlib.sha3_256(dados).digest()


def converte_bytes(y: bytes): # Faz a conversão de uma string de bytes para um inteiro. 
    return int.from_bytes(y, byteorder = 'big', signed = False)


def converte_string_oct(y: int, tamanho: int): # Converte um inteiro que não seja negativo em string de octetos de um comprimento especificado.
    return y.to_bytes(tamanho, byteorder = 'big', signed = False)


def sha3(dados: bytes):  # Função de hash Sha 3.
    hasher = hashlib.sha3_256()
    hasher.update(dados)
    return hasher.digest()


def MGF1(geracao: bytes, tamanho_calda: int): # Função de Geração de Máscara com SHA-3 para proteção do arquivo.
    mascara_hash = b''
    tamanho_len = len(sha3(b''))
    for c in range (0, math.ceil(tamanho_calda / tamanho_len)):
        tempo_execucao_c = c.to_bytes(4, byteorder = "big")
        mascara_hash += sha3(geracao + tempo_execucao_c)
    return mascara_hash[:tamanho_calda]


def xor(date: bytes, mascara: bytes): # Duas cadeias de bytes juntos, que é usado no OEAP.
    return bytes([_x ^ _y for _x, _y in zip(date, mascara)])


def cifracao_oaep(message: string, z: int, c0: int, c1: int): #Preenchimento de OAEP usado antes da criptografia do RSA.
    for i in range(c1): # Adicionando zeros a mensagem.
        message += str(0)

    gera = string.ascii_lowercase + string.digits # Gera um r de tamanho aleatório c0.
    r = ''.join(random.SystemRandom().choice(gera) for _ in range(c0))

    expansao = MGF1(bytes(r, "utf-8"), z - c0) # Usando um oráculo para expandir r de c0 para z - c0 de tamanho arbitrário.

    x = xor(bytes(message, "utf-8"), expansao) # Expansão das cadeias de bytes utilizando o XOR para expandir o "m".
    y = xor(bytes(r, "utf-8"), sha3(x)) # Expansão das cadeias de bytes utilizando o XOR para expandir o "r".


    resultado_oaep_cifra = b''.join([x, y]) # Juntando o resultado dos bytes "x" e "y".

    return x, y, resultado_oaep_cifra


def decifracao_oaep(x: bytes, y: bytes, n = 1024, padding = 32): # Inverso da cifração do oaep.

    r = xor(y, sha3(x))
    message = xor(x, MGF1(r, n - padding))

    
    message = str(message, 'utf-8', 'replace') # Transformamos os bytes em string e removemos.
    message = str(message).replace("0", "") # Inserindo 0 nos caracteres.

    return r, message 


def cifracao_rsa(messasgecifrada, chave_publica: dict): # Criptografa uma mensagem usando a tupla de chaves públicas.
    z, l, mensagem = cifracao_oaep(messasgecifrada, 1024, 32, 16)

    c = pow(converte_bytes(mensagem), chave_publica['public'], chave_publica['n'])

    rsa_cifracao = { 'z': len(z), 'l': len(l), 'mensagem': len(mensagem), 'Criptografado': c}

    return rsa_cifracao 


def decifracao_rsa(data: dict, chave_privada: dict): # Decifra utilizando tupla de chaves privadas.
    mensagem = pow(data['Criptografado'], chave_privada['priv'], chave_privada['n']) 

    z = data['z']
    l = data['l']

    bytes = converte_string_oct(mensagem, data['mensagem'])
    message_cifrada = decifracao_oaep(bytes[:z], bytes[z:z + l])

    return message_cifrada[1]


def certificado_de_assinatura(dados, chave_privada, chave_publica): # Assinando o hash dos dados e devolvendo ao usuário.
    assinatura = pow(converte_bytes(dados), chave_privada['priv'], chave_publica['n'])
    assinatura = converte_string_oct(assinatura, 1024)

    return assinatura


def validacao(dados, assinatura, chave_publica): # Verifica se a assinatura está realmente assinada com a chave pública.
    hashed = sha3(dados)
 
    validacao = pow(converte_bytes(assinatura), chave_publica['public'], chave_publica['n'])
    validacao = converte_string_oct(validacao, 32)
    
    if validacao != hashed:
        return False
        
    return True


def criando_um_parsing(): # Criando uma análise de um documento.

    parsing = argparse.ArgumentParser(description = 'Algoritmo RSA')

    parsing.add_argument('-encript', '--encriptacao', help='encriptacao dos dados', default=False,
                        action='store_true')
    parsing.add_argument('-decript', '--decriptacao', help='decriptacao dos dados', default=False,
                        action='store_true')

    parsing.add_argument('-geracaoparprimo', '--gera-par-primo', default=False,
                        action='store_true',
                        help='gera o par de chave publica/privada'
                        + ' a encriptacao e decriptacao')

    parsing.add_argument('-descricaochave', '--descricaochave', help='Uma chave publica ou privada usada para'
                        + ' encriptar ou descriptar os dados')
    parsing.add_argument('-arquivo', '--arquivo', help='arquivo a ser criptografado ou'
                        + 'descriptografado dado uma chave')

    parsing.add_argument('-valida', '--verificacao', nargs='+', help='verificacao de uma assinatura')
    parsing.add_argument('-assinaturadoarquivo', '--assinar', nargs='+', help='faz uma assinatura para'
                        + 'um dado arquivo')

    return parsing


def main():
    parsing = criando_um_parsing().parse_args()  

    if(parsing.gera_par_primo):
        chave_publica = {}
        chave_privada = {}

        print('Gerando chaves publicas e privadas ...\n')
        p = geracao_dos_primos(1024)
        q = geracao_dos_primos(1024)

        chave_publica, chave_privada = gerador_de_chaves_rsa(p, q)
        arquivo.escrevendo_chaves('chave_privada.priv', chave_privada)
        arquivo.escrevendo_chaves('chave_publica.public', chave_publica)

    if (parsing.encriptacao or parsing.decriptacao):
        if(parsing.arquivo is None): # Imprimindo o uso do programa.
            print("Usando: python3 Gerador-Verificador-de-Assinaturas-RSA-Arquivos.py -encript/decript -arquivo <arquivo> -descricaochave <descricaochave>") 
            sys.exit(1)
        
        if(parsing.descricaochave is None):
            print('Chave inexistente para criptografia/descriptografia')
            sys.exit(1)
      
        chave_publica = {}
        chave_privada = {}

        if(parsing.encriptacao):
            chave_publica = arquivo.lendo_chaves(parsing.descricaochave)
            inform_arquivo = arquivo.lendo(parsing.arquivo)
            mensagem_encriptada = cifracao_rsa(inform_arquivo, chave_publica)   
            arquivo.escrita_criptograma(parsing.arquivo + ".encript", mensagem_encriptada)

        elif(parsing.decriptacao):
            chave_privada = arquivo.lendo_chaves(parsing.descricaochave)
            dados_descriptados = arquivo.lendo_criptograma(parsing.arquivo)
            decifra = decifracao_rsa(dados_descriptados, chave_privada)
            arquivo.escrita(parsing.arquivo + ".decript", decifra)
  
    elif(parsing.assinar):
        chave_publica = {}
        chave_privada = {}
          
        file = ''

        for arg in parsing.assinar: # Lendo uma chave privada e pública e os dados para certificar a assinatura.
            if arg.endswith('.public'):
                chave_publica = arquivo.lendo_chaves(arg)
            elif arg.endswith('.priv'):
                chave_privada = arquivo.lendo_chaves(arg)
            else: 
                file = arg
    
        print(f'\nAssinando arquivo {file} com chaves...')
        texto = arquivo.lendo(file)
        hashed = sha3(bytes(file, 'utf-8'))

        assinatura = certificado_de_assinatura(hashed, chave_privada, chave_publica)
        codificado_assinatura = base64.b64encode(assinatura)
        arquivo.escrita(file + ".assinatura", str(codificado_assinatura, 'utf-8'))

    elif(parsing.verificacao):  
        chave_publica = {}
        file = ''
        assinatura = ''
      
        for arg in parsing.verificacao:
            if arg.endswith('.public'):
                chave_publica = arquivo.lendo_chaves(arg)
            elif arg.endswith('.assinatura'):
                assinatura = arquivo.lendo(arg)
            else:
                file = arg
  
        texto = bytes(arquivo.lendo(file), 'utf-8')
        decodificacao_assinatura = base64.b64decode(assinatura)
        valida = validacao(texto, decodificacao_assinatura, chave_publica)

        if valida:
            print("\nAssinatura esta valida!")
        else:
            print("\nAssinatura esta invalida!")

    input("Pressione Enter para fechar.") # Trava a tela do usuário.
main()