from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
import cryptography.exceptions

def genkeys():
    #Generates a key pair: sk - secret key used to sign msgs and pk - public key used to verify msgs
    sk = ec.generate_private_key(ec.SECP256K1, default_backend())
    pk = sk.public_key()
    return sk, pk
    
def sign(sk,msg):
    #Takes msg and sk and outputs signature for msg
    sig = sk.sign(msg,ec.ECDSA(hashes.SHA256()))
    return sig

def verify(pk,sig,msg):
    #Takes msg public key and signature and returns boolean 
    try:
        pk.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
        return True
    except: 
        return False