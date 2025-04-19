import pysodium
import psutil
import os

def symmetric_encrypt(data,k):
    nonce=os.urandom(pysodium.crypto_secretbox_NONCEBYTES)
    c=pysodium.crypto_secretbox(data,nonce,k)
    return (nonce,c)

def symmetric_decrypt(nonce,c,k):
    try:
        m=pysodium.crypto_secretbox_open(c,nonce,k)
        return m
    except ValueError:
        print("解密失败")
        return None