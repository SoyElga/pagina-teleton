def write_private_key(private_key: int, path: str) -> None:
    ''' Funcion que recibe una clave privada como entero. 
    Escribe esta firma a el archivo private.pemen formato 
    hexadecimal
    Si la escritura falla, levanta una excepcion'''
    try:
        with open(path, 'w') as f:
            f.write("-----BEGIN EC KEY FILE-----\n")
            f.write(str(hex(private_key)))
            f.write("\n-----END EC KEY FILE-----")
    except:
        raise


def write_public_key(Q: 'tuple[int,int]') -> None:
    ''' Funcion que recibe una clave publica en formato (Qx,Qy),
    y un nombre de archivo. Escribe esta firma a el archivo public.pem 
    en formato hexadecimal. Si la escritura falla, levanta una excepcion'''
    try:
        with open("public.pem", 'w') as f:
            f.write("-----BEGIN EC KEY FILE-----\n")
            f.write(str(hex(Q[0])))
            f.write(",\n")
            f.write(str(hex(Q[1])))
            f.write("\n-----END EC KEY FILE-----")
    except:
        raise


def sig_write(signature: 'tuple[int,int]',filename: str) -> None:
    ''' Función que recibe una firma en formato (r,s), y un nombre de 
    archivo. Escribe esta firma a el archivo <filename>+signature.pem
    en formato hexadecimal
    Si la escritura falla, levanta una excepción'''
    try:
        with open(filename+"signature.pem", 'w') as f:
            f.write("-----BEGIN EC SIGNATURE FILE-----\n")
            f.write(str(hex(signature[0])))
            f.write(",\n")
            f.write(str(hex(signature[1])))
            f.write("\n-----END EC SIGNATURE FILE-----")
    except:
        raise



def sig_read(filename: str) -> 'tuple[int,int]':
    '''Funcion que recibe un nombre de un archivo generado por
    la función sig_write. Lee las lineas que contienen la firma 
    y la convierten de vuelta a un entero. Devuelve una tupla 
    (r,s)'''
    file1 = open(filename, 'r')
    Lines = file1.readlines()
    if Lines[0]!='-----BEGIN EC SIGNATURE FILE-----\n':
        # Excepcion levantada cuando se introduce algo que no es una firma
        raise
    Lines.pop(-1)
    Lines.pop(0)
    Lines[0]=Lines[0].replace(',\n','')
    Lines[1]=Lines[1].replace(',\n','')
    return (int(Lines[0],base=16),int(Lines[1],base=16))



def public_key_read(filename: str) -> 'tuple[int,int]':
    '''Funcion que recibe un nombre de un archivo generado por
    la función write_public_key. Lee las lineas que contienen la clave 
    y la convierten de vuelta a un entero. Devuelve una tupla 
    (r,s)'''
    file1 = open(filename, 'r')
    Lines = file1.readlines()
    if Lines[0]!='-----BEGIN EC KEY FILE-----\n' or len(Lines)!=4:
        # Excepcion levantada cuando se introduce algo que no es una clave publica
        raise
    Lines.pop(-1)
    Lines.pop(0)
    Lines[0]=Lines[0].replace(',\n','')
    Lines[1]=Lines[1].replace(',\n','')
    return (int(Lines[0],base=16),int(Lines[1],base=16))

def private_key_read(filename: str) -> int:
    '''Funcion que recibe un nombre de un archivo generado por
    la función write_private_key. Lee las lineas que contienen la clave 
    y la convierten de vuelta a un entero. Devuelve el entero'''
    file1 = open(filename, 'r')
    Lines = file1.readlines()
    if Lines[0]!='-----BEGIN EC KEY FILE-----\n' or len(Lines)!=3:
        # Excepcion levantada cuando se introduce algo que no es una clave publica
        raise
    Lines.pop(-1)
    Lines.pop(0)
    Lines[0]=Lines[0].replace(',\n','')
    return int(Lines[0],base=16)
