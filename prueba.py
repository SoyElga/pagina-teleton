from curve_data import P_256
from readWrite import  write_private_key, private_key_read, sig_write, sig_read
from ECDSA_keyGenerator import *
from signVerify import *

def generate_key():
    '''Genera instancia de clave privada y publica'''
    curve=P_256()
    private_key = secure_random(curve.n)
    publicKey = public_key(curve,private_key)
    return (private_key,publicKey.Q)

private, public = generate_key()

rs, fingerprint = sign_doc(private, P_256(), "certificates\public_key\luisga_private_key_certificate.pdf")

print(private)
print(public)
print(rs)

PK_curve_form=P_256()
PK_curve_form.Q=public

print(verify(rs, P_256(), PK_curve_form, "certificates\public_key\luisga_private_key_certificate.pdf"))