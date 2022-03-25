from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import argparse

def serializar_llave_privada(path_llave):
	archivo_llave = open(path_llave, 'rb')
	llave_bytes = archivo_llave.read()
	archivo_llave.close()
	#print(llave_bytes)
	private_key = serialization.load_pem_private_key(
		llave_bytes,
		backend=default_backend(),
		password=None)
	return private_key

def serializar_llave_publica(path_llave):
	archivo_llave = open(path_llave, 'rb')
	llave_bytes = archivo_llave.read()
	archivo_llave.close()
	public_key = serialization.load_pem_public_key(
		llave_bytes,
		backend= default_backend())
	return public_key


def cifrar(path_entrada, path_salida, path_llave_publica):
	public_key = serializar_llave_publica(path_llave_publica)
	salida = open(path_salida, 'wb')
	for buffer in open(path_entrada, 'rb'):
		ciphertext = public_key.encrypt(
	    	buffer,
	    	padding.OAEP(
	    		mgf = padding.MGF1(algorithm = hashes.SHA256()),
	    		algorithm = hashes.SHA256(),
	    		label = None)) # se usa rara vez dejar None
		#print(len(ciphertext))
		salida.write(ciphertext)
	salida.close()


def descifrar(path_entrada, path_salida, path_llave_privada):
	private_key= serializar_llave_privada(path_llave_privada)
	salida=open(path_salida, 'wb')

	entrada = open(path_entrada, 'rb')
	contenido = entrada.read()
	lista_contenido = list(contenido)
	inicio = 0
	fin = 256
	while lista_contenido:
		linea=lista_contenido[inicio:fin]
		if len(linea) != 0:
			recovered = private_key.decrypt(
				linea,
				padding.OAEP(
					mgf = padding.MGF1(algorithm = hashes.SHA256()),
					algorithm = hashes.SHA256(),
					label = None))
		
			salida.write(recovered)
			inicio=inicio+256
			fin=fin+256
		else:
			print("Descifrado Correcto")
			salida.close()
			break
	
if __name__ == '__main__':
  all_args =  argparse.ArgumentParser()
  all_args.add_argument("-p", "--Operacion", help="Aplicar operación, cifrar/descifrar", required=True)
  all_args.add_argument("-i", "--input", help="Archivo de entrada", required=True)
  all_args.add_argument("-o", "--output", help="Archivo de salida", required=True)
  all_args.add_argument("-l", "--llave", help="Archivo con la llave", required=True)

  args = vars(all_args.parse_args())
  operacion = args['Operacion']

  if operacion == 'cifrar':
  	cifrar(args['input'], args['output'], args['llave'])
  else:
  	descifrar(args['input'], args['output'], args['llave'])
