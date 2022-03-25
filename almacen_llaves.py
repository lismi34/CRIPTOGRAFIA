from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import argparse
import gmpy2, os, binascii

# Generar y almacenar llaves
def generar_llaves(path_salida_publica, path_salida_privada):
  private_key = rsa.generate_private_key(
      public_exponent=65537,
      key_size=2048,
      backend=default_backend())

  private_key_bytes = private_key.private_bytes(
    encoding = serialization.Encoding.PEM,
    format= serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
  )

  archivo_privada = open(path_salida_privada, 'wb')
  archivo_privada.write(private_key_bytes)
  archivo_privada.close()

  public_key = private_key.public_key()
  public_key_bytes=public_key.public_bytes(
    encoding = serialization.Encoding.PEM,
    format= serialization.PublicFormat.SubjectPublicKeyInfo
  )

  archivo_publica = open(path_salida_publica, 'wb')
  archivo_publica.write(public_key_bytes)
  archivo_publica.close()


if __name__ == '__main__':
  all_args =  argparse.ArgumentParser()
  all_args.add_argument("-a", "--rutaPublica", help="Ruta llave pública", required=True)
  all_args.add_argument("-b", "--rutaPrivada", help="Ruta llave privada", required=True)

  args = vars(all_args.parse_args())
  generar_llaves(args['rutaPublica'], args['rutaPrivada'])
