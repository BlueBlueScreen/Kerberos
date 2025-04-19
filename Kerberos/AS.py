import sys
import socket
import time
import pysodium
from security import symmetric_encrypt,symmetric_decrypt
import hashlib
import struct
from database import db, users_collection,keys_collection
from fontTools.misc.filenames import userNameToFileName
from security import symmetric_decrypt, symmetric_encrypt

# 规定标准的长度
MAX_ID_BYTES = 64
KEY_LEN = 32
TS_LEN = 8
NONCE_LEN = 24
MAC_LEN=16

def create_server(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.bind(('0.0.0.0', port))
    sock.listen(1)
    return sock


def connect_socket(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    try:
        sock.connect((ip, port))
    except Exception as e:
        print(f"连接失败: {e}")
        exit(1)
    return sock

def AS_execution():
    if len(sys.argv)!=3:
        print(f"Usage:{sys.argv[0]} --listen port")
        exit(1)

    port=int(sys.argv[2])
    listen_sock=create_server(port)
    print(f"Listening on port {port}……")

    sock,addr=listen_sock.accept()

    #每个服务器都是先收后发的哈
    data=b''
    expected_len=2*MAX_ID_BYTES+TS_LEN

    while len(data)<expected_len:
        data+=sock.recv(4096)

    username=data[:MAX_ID_BYTES].rstrip(b'\0').decode()
    id_tgs_received=data[MAX_ID_BYTES:2*MAX_ID_BYTES]
    ts_1=struct.unpack('>d',data[-TS_LEN:])[0]
    if abs(time.time()-ts_1)>300:
        print("时间戳已过期")
        exit(1)

    user=users_collection.find_one({'username':username})
    if not user:
        print("用户不存在")
        exit(1)
    password_hash=user.get("password_hash")
    if not password_hash:
        print("用户口令哈希值不存在")
        exit(1)

    #去掉盐值，拿到共享密钥

    k=password_hash[16:]

    K_c_tgs=pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
    ts_2=time.time()
    ls_2=3600 #票据有效期设置为一个小时
    username_encoded=username.encode()[:MAX_ID_BYTES].ljust(MAX_ID_BYTES,b'\0')
    ts_2_encoded=struct.pack('>d',ts_2)
    ls_2_encoded=struct.pack('>d',ls_2)

    key=keys_collection.find_one({'key_name':'tgs_as'})
    k_tgs=key.get('key')
    if not k_tgs:
        print("密钥不存在")
        exit(1)

    ticket=K_c_tgs+username_encoded+id_tgs_received+ts_2_encoded+ls_2_encoded
    nonce_as_tgs,Ticket_tgs=symmetric_encrypt(ticket,k_tgs)
    Ticket_tgs+=nonce_as_tgs
    messages=K_c_tgs+id_tgs_received+ts_2_encoded+ls_2_encoded+Ticket_tgs
    nonce_as_c,m=symmetric_encrypt(messages,k)
    sock.sendall(m+nonce_as_c)

    sock.close()

if __name__ == "__main__":
    AS_execution()