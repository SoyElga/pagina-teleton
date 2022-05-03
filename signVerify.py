from copy import deepcopy
import hashlib
from hashlib import sha512
from ECDSA_keyGenerator import secure_random, curve, public_key
#from database_manager import get_certificate, get_keys,get_public_keys, write_certificate
from datetime import datetime,timedelta

def write_fingerprint(huella):
    fingerprint=sha512(str(huella).encode()).hexdigest()
    return fingerprint

#Se cambio el nombre de sign a sign_doc
def sign_doc(private_key: int, curve: curve, message_or_filename, hashFunc: hashlib= hashlib.sha512(),test_k: int= None) -> 'tuple[int,int]':
    '''Funcion que genera la firma digital de un archivo en formato
    (r,s), recibe la clave privada, la curva a usar, el nombre del archivo 
    (o en caso de testing el texto en bytes), la funcion hash
    a usar y en caso de testing la k proporcionada'''
    "Por defecto se usa SHA256 y no se da una k"
    r,s=0,0
    BUF_SIZE = 65536 
    # El caso de str es usadado para testing
    # si se da un nombre de archivo se abre
    # y hashea al correr, de lo contrario
    # se hashea directamente el contenido
    if type(message_or_filename)==str:
        with open(message_or_filename, 'rb') as f: # Open the file to read it's bytes
            fb = f.read(BUF_SIZE) # Read from the file. Take in the amount declared above
            while len(fb) > 0: # While there is still data being read from the file
                hashFunc.update(fb) # Update the hash
                fb = f.read(BUF_SIZE) # Read the next block from the file
    else:
        e=hashFunc.update(message_or_filename)
    e=hashFunc.hexdigest()
    # Dado que algunos hashes producen resultados de mas de 256 bits, se toman los primeros 
    # 256, lo que es equivalente a las primeras 64 posiciones hexadecimales
    if len(e)>64:
        e=e[:64]
    e=int(e,base=16)%curve.n
    while r ==0 or s==0:
        # Genera k, usada para firmar
        k=secure_random(curve.n)
        # Usado por el modulo de testing, si se está testeando k
        # es dada
        if test_k!=None:
            k=test_k 
        curve=public_key(curve,k)
        r=curve.Q[0]%curve.n
        # Verifica si r=0, en caso de ser asi ahorra las computaciones
        # subsecuentes, regresa al inicio del loop
        if r==0:
            continue
        j=pow(k,-1,curve.n)
        # En caso de que s==0, el loop se reinicia
        s=(j*(e+private_key*r))%curve.n
    # Tras haber hecho todas las computaciones, se verifica si la persona 
    # tiene credenciales vigentes para firmar. Si es el caso devuelve el 
    # resultado. Si no lo es, levanta una excepcion. Se omite si se esta
    # haciendo testing
    if test_k== None:
        fingerprint = write_fingerprint(r)
        #try:
        #    #Se comenta todo esto ya que la verificacion de vigencia de la firma se hace antes de llamar la función   
        #    #            signer_data=get_keys(private_key)
        #    #            # Verifica que la persona tenga vigencia para firmar
        #    #            assert(datetime.now()<=datetime.strptime(signer_data[6],"%Y-%m-%d %H:%M:%S"))
        #    #            #Escribe el certificado
        #except:
        #    raise
    return ((r,s), fingerprint) 

'''
#Se cambio el nombre de sign a sign_doc
def sign_doc(private_key: int, curve: curve, message_or_filename, hashFunc: hashlib= hashlib.sha512(),test_k: int= None) -> 'tuple[int,int]':
    Funcion que genera la firma digital de un archivo en formato
    (r,s), recibe la clave privada, la curva a usar, el nombre del archivo 
    (o en caso de testing el texto en bytes), la funcion hash
    a usar y en caso de testing la k proporcionada
    "Por defecto se usa SHA256 y no se da una k"
    r,s=0,0
    BUF_SIZE = 65536 
    El caso de str es usadado para testing
    si se da un nombre de archivo se abre
    y hashea al correr, de lo contrario
    se hashea directamente el contenido
    if type(message_or_filename)==str:
        with open(message_or_filename, 'rb') as f: # Open the file to read it's bytes
            fb = f.read(BUF_SIZE) # Read from the file. Take in the amount declared above
            while len(fb) > 0: # While there is still data being read from the file
                hashFunc.update(fb) # Update the hash
                fb = f.read(BUF_SIZE) # Read the next block from the file
    else:
        e=hashFunc.update(message_or_filename)
    e=hashFunc.hexdigest()
    Dado que algunos hashes producen resultados de mas de 256 bits, se toman los primeros 
    256, lo que es equivalente a las primeras 64 posiciones hexadecimales
    if len(e)>64:
        e=e[:64]
    e=int(e,base=16)%curve.n
    while r ==0 or s==0:
        Genera k, usada para firmar
        k=secure_random(curve.n)
        Usado por el modulo de testing, si se está testeando k
        es dada
        if test_k!=None:
            k=test_k 
        curve=public_key(curve,k)
        r=curve.Q[0]%curve.n
        Verifica si r=0, en caso de ser asi ahorra las computaciones
        subsecuentes, regresa al inicio del loop
        if r==0:
            continue
        j=pow(k,-1,curve.n)
        En caso de que s==0, el loop se reinicia
        s=(j*(e+private_key*r))%curve.n
    Tras haber hecho todas las computaciones, se verifica si la persona 
    tiene credenciales vigentes para firmar. Si es el caso devuelve el 
    resultado. Si no lo es, levanta una excepcion. Se omite si se esta
    haciendo testing
    if test_k== None:
        fingerprint = write_fingerprint(r)
        try:
           Se comenta todo esto ya que la verificacion de vigencia de la firma se hace antes de llamar la función   
                      signer_data=get_keys(private_key)
                      # Verifica que la persona tenga vigencia para firmar
                      assert(datetime.now()<=datetime.strptime(signer_data[6],"%Y-%m-%d %H:%M:%S"))
                      #Escribe el certificado
        except:
           raise
    print("(r,s), fingerprint")
    return ((r,s), fingerprint) 
'''

def verify(signature: 'tuple[int,int]', curve: curve, publicKey: curve, message_or_filename,hashFunc: hashlib= hashlib.sha512()) -> bool:
    '''Funcion que verifica que la firma dada sea valida,
    recibe la firma, la curva usada, la clave publica, 
    y el nombre del archivo (o en caso de testing 
    el texto en bytes), y la funcion hash a usar'''
    "Por defecto se usa sha256"
    if signature[0]==0 or signature[0]>(curve.n-1) or signature[1]==0 or signature[1]>(curve.n-1):
        return False
    w=pow(signature[1],-1,curve.n)
    # El caso de str es usadado para testing
    # si se da un nombre de archivo se abre
    # y hashea al correr, de lo contrario
    # se hashea directamente el contenido
    BUF_SIZE = 65536 
    # El caso de str es usadado para testing
    # si se da un nombre de archivo se abre
    # y hashea al correr, de lo contrario
    # se hashea directamente el contenido
    if type(message_or_filename)==str:
        with open(message_or_filename, 'rb') as f: # Open the file to read it's bytes
            fb = f.read(BUF_SIZE) # Read from the file. Take in the amount declared above
            while len(fb) > 0: # While there is still data being read from the file
                hashFunc.update(fb) # Update the hash
                fb = f.read(BUF_SIZE) # Read the next block from the file
    else:
        #Como esto sucede solo en testing, se da como valida la vigencia de la firma
        u=hashFunc.update(message_or_filename)
        valid_timeframe=True
    u=hashFunc.hexdigest()
    # Dado que algunos hashes producen resultados de mas de 64 bits, se toman los primeros 
    # 256, lo que es equivalente a las primeras 64 posiciones hexadecimales
    if len(u)>64:
        u=u[:64]
    u=int(u,base=16)%curve.n
    u_1=(w*u)%curve.n
    u_2=(signature[0]*w)%curve.n
    u_1P=deepcopy(curve)
    u_1P=public_key(u_1P,u_1)
    # Se hace para poder calcular U_2*D
    publicKey.G=publicKey.Q
    u_2P=public_key(publicKey,u_2)
    # Se computa U_1P+u_2D
    curve.point_adition(u_1P.Q,u_2P.Q,False)
    v=curve.Q[0]%curve.n
    # Tras haber hecho todas las computaciones, se verifica si la persona 
    # tiene credenciales vigentes para firmar. Si es el caso devuelve el 
    # resultado. Si no lo es, levanta una excepcion. Se omite si se esta
    # haciendo testing
    #try:
    #    # Se verifica con G por que Q fue usado para computaciones anteriormente
    #    signer_data=get_public_keys(publicKey.G)
    #    # Verifica que la firma tenga vigencia (no importa si la persona
    #    # no tiene vigencia para firmar, pues pudo haber firmado cuando si tenia)
    #    certificate_data=get_certificate(signer_data[0],v)
    #    certificate_expiration=datetime.strptime(certificate_data[2],"%Y-%m-%d %H:%M:%S.%f")
    #    valid_timeframe=datetime.now()<=certificate_expiration  
    #except:
        #pass
    #Se quitó el valid?timeframe ya que ese se verifica antes de llamar la función  
    print(signature[0])  
    print(v)
    if signature[0]==v:
        return True
    return False
