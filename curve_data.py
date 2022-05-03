from ECDSA_keyGenerator import curve
def P_256() -> curve:
    '''Curva NIST P-256'''
    name="P-256"
    # Orden del campo
    p   =int(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff)
    a   =int(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
    b	=int(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
    G	=(int(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296), 
    int(0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5))
    # Orden del generador
    n	=int(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551)
    h	=int(0x1)
    return curve(name,(a,b),p,G,n,h)

