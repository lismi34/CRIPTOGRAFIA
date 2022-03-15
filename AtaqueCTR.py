import os
import argparse
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def calcular_xor(binario1, binario2):
    bytes1 = list(binario1)
    bytes2 = list(binario2)
    longitud_menor = len(bytes1)
    lista_larga = bytes2

    if len(bytes2) < longitud_menor:
        longitud_menor = len(bytes2)
        lista_larga = bytes1

    res_bytes=[]

    for i in range(longitud_menor):
        res_bytes.append(bytes1[i] ^ bytes2[i])

    return bytes(res_bytes) + bytes(lista_larga[longitud_menor:])

def cifrar(llave, nonce):
    i = 0
    aesCipher = Cipher(algorithms.AES(llave),
                       modes.CTR(nonce),
                       backend = default_backend)
    aesEncryptor = aesCipher.encryptor()

    salida = open('./nuevo.cif', 'wb')
    for buffer in open('./atacante.xml', 'rb'):
        print("BUFFER:",buffer)
        cifrado = aesEncryptor.update(buffer)
        if i == 2:
            key_stream = calcular_xor(cifrado, buffer)
            texto_falso= b'    <Merchant>Liset MI</Merchant>\n'
            cifrado = calcular_xor(texto_falso, key_stream)

        salida.write(cifrado)
        i = i+1

    aesEncryptor.finalize()
    salida.close()


def descifrar(llave, nonce):
    aesCipher = Cipher(algorithms.AES(llave),
                       modes.CTR(nonce),
                       backend = default_backend)
    aesDecryptor = aesCipher.decryptor()

    salida = open('./nuevo.xml', 'wb')
    for buffer in open('./nuevo.cif', 'rb'):
        plano= aesDecryptor.update(buffer)
        salida.write(plano)
        
    aesDecryptor.finalize()
    salida.close()

if __name__ == '__main__':
    all_args =  argparse.ArgumentParser()
    all_args.add_argument("-p", "--Operacion", help="Aplicar operación, cifrar/descifrar")
    all_args.add_argument("-l", "--llave", help="Llave", required=True)
    all_args.add_argument("-n", "--Nonce", help="IV", required=True)
    
    args = vars(all_args.parse_args())
    operacion = args['Operacion']

    # Preparar llave recibida en base64
    key = base64.b64decode(args['llave'])
    iv = base64.b64decode(args['Nonce'])

    print(len(key))
    if (len(key) != 16) or (len(iv) != 16):
        print('Verificar tamaño de la Llave o IV, debe ser de 16 bytes')
        exit()
    
    if operacion == 'cifrar':
        cifrar(key, iv)
    else:
        descifrar(key, iv)


