import os
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


def descifrar(entrada, key, iv):
    aesCipher = Cipher(algorithms.AES(key),
                       modes.CTR(iv),
                       backend = default_backend)

    aesDecryptor = aesCipher.decryptor()
    plano = aesDecryptor.update(entrada)
    print("P:", plano)
    aesDecryptor.finalize()
    return plano
  
def cifrar(entrada, llave, nonce):
    aesCipher = Cipher(algorithms.AES(llave),
                       modes.CTR(nonce),
                       backend = default_backend)
    aesEncryptor = aesCipher.encryptor()
    c = aesEncryptor.update(entrada)
    print(c)
    aesEncryptor.finalize()
    return c 



key = os.urandom(16)
iv = os.urandom(16)

i = 0
salida = open("salida.cif", 'wb')
for buffer in open('./atacante.xml', 'rb'):
	if i == 2:
		key_stream = calcular_xor(cifrado, descifrado)
		print(key_stream)
		texto_falso= b'<Merchant>Liset MI</Merchant>'
		key=key_stream
		cifrado = cifrar(texto_falso, key, iv)
		descifrado = descifrar(cifrado, key, iv)
	else:
		cifrado = cifrar(buffer, key, iv)
		descifrado = descifrar(cifrado, key, iv)

	salida.write(cifrado)
		

	i=i+1	

salida.close()

