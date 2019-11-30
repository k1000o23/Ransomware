
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import zlib
import base64
import sys

#Funcion de cifrado
def cifrado(f, public_key):
    #Se importa la Public Key ciframos con PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    #Comprimimos los datos para que sea mas rapido
    f = zlib.compress(f)

    #El cifrado se hace en bloques
    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted =  ""

    while not end_loop:
        #The chunk
        chunk = f[offset:offset + chunk_size]

        #Si ya hemos fragmentado al maximo ponemos un padding para terminar de cifrar
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += " " * (chunk_size - len(chunk))

        #Juntamos todo
        encrypted += rsa_key.encrypt(chunk)

        #Se incrementa el offset
        offset += chunk_size

    #Y por ultimo pasamos todo a base64
    return base64.b64encode(encrypted)

#Se cifra con la clave publica
fd = open("public_key.pem", "rb")
public_key = fd.read()
fd.close()

#Archivo que vamos a cifrar
fd = open(sys.argv[1], "rb")
archivo = fd.read()
fd.close()

cifrado = cifrado(archivo, public_key)

#Write the encrypted contents to a file
fd = open(sys.argv[1]+".encrypted", "wb")
fd.write(cifrado)
fd.close()
