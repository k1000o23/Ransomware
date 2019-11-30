from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import zlib
import sys 

#Our Decryption Function
def descifra(f, private_key):

    #Se importa la Private Key ciframos con PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    #Base 64 decode
    f = base64.b64decode(f)

    #Chunk_size viene dato por la long. de la priv.key en bytes.
    chunk_size = 512
    offset = 0
    decrypted = ""

    #Buscamos bloques para descifrar
    while offset < len(f):

        chunk = f[offset: offset + chunk_size]
        decrypted += rsakey.decrypt(chunk)

        #Aumentamos offset
        offset += chunk_size

    #Descomprimimos los datos descifrados
    return zlib.decompress(decrypted)

#Usamos la Private Key para descifrar
fd = open("private_key.pem", "rb")
private_key = fd.read()
fd.close()

#Fichero a descifrar
fd = open(sys.argv[1], "rb")
archivo = fd.read()
fd.close()

#Guardamos al salida
fd = open( sys.argv[1]+".decrypted", "wb")
fd.write(descifra(archivo, private_key))
fd.close()
