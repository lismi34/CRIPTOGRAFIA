
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography. hazmat.primitives.ciphers import Cipher, algorithms, modes

import os
import argparse
import getpass

def generar_llave(password: str, salt: bytes):
    """
    Función para derivar una llave a partir de un password.

    Keyword Arguments:
    password: str
    salt: bytes
    returns: bytes
    """
    password_bin = password.encode('utf-8')
    kdf = Scrypt(salt=salt, length = 32, n =2**14, r =8, p=1, backend=default_backend())
    key = kdf.derive(password_bin)
    return key


def cifrar(inputPath: str, outPath: str, password: str):
    """
    Cifrar un archivo con AES GCM.

    Keyword Arguments:
    inputPath ruta de archivo plano a cifrar
    outputPath ruta del archivo cifrado resultante
    password  str
    returns: None, crea un achivo
    """
    iv = os.urandom(12)
    salt = os.urandom(16)
    key = generar_llave(password, salt)
    datos_adicionales = iv + salt

    encryptor = Cipher(algorithms.AES(key),
                       modes.GCM(iv),
                       backend = default_backend()).encryptor()

    encryptor.authenticate_additional_data(datos_adicionales)

    salida = open(outPath, 'bw')
    for buffer in open(inputPath, 'rb'):
        cifrado = encryptor.update(buffer)
        salida.write(cifrado)

    encryptor.finalize()
    tag = encryptor.tag

    salida.write(iv) # 12 bytes
    salida.write(salt) # 16 bytes
    salida.write(tag) # 16 bytes         
    salida.close()

def obtener_iv_tag_salt(inputPath: str):
    archivo=open(inputPath, 'br')
    archivo.seek(0,2)
    tam=archivo.tell()
    archivo.seek(archivo.tell()-44)
    
    datos=archivo.read()
    iv=datos[:12]
    salt=datos[12:28]
    tag=datos[28:]
    return iv,salt,tag, tam
        
def descifrar(inputPath: str, outPath: str, password: str):
    iv, salt, tag, tam= obtener_iv_tag_salt(inputPath)
    key=generar_llave(password, salt)
    decryptor = Cipher(algorithms.AES( key),
                        modes.GCM(iv, tag) ,
                        backend = default_backend()).decryptor()

    associated_data = iv + salt
    decryptor.authenticate_additional_data(associated_data)

    salida = open(outPath, 'bw')

    entrada=open(inputPath, 'rb')
    for buffer in entrada:
        if entrada.tell() == tam:
            print(buffer[:-44])
            plano=decryptor.update(buffer[:-44])
        else:
            plano=decryptor.update(buffer)
        salida.write(plano)
    salida.close()

    try:
        decryptor.finalize()
        print('Pasó la verificación de tag, todo OK')
    except:
        print('No pasó la verificación de tag, integridad comprometida')


if __name__ == '__main__':
    all_args =  argparse.ArgumentParser()
    all_args.add_argument("-p", "--Operacion", help="Aplicar operación, cifrar/descifrar")
    all_args.add_argument("-i", "--input", help="Archivo de entrada", required=True)
    all_args.add_argument("-o", "--output", help="Archivo de salida", required=True)
    args = vars(all_args.parse_args())
    operacion = args['Operacion']
    password = getpass.getpass(prompt='Password: ')

    if operacion == 'cifrar':
        cifrar(args['input'], args['output'], password)
    elif operacion == 'descifrar':
        descifrar(args['input'], args['output'], password)
