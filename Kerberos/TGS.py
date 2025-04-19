import sys
import socket
import time
import pysodium
from networkx.algorithms.coloring.greedy_coloring import strategy_smallest_last

from security import symmetric_encrypt,symmetric_decrypt
import hashlib
import struct
from database import db, users_collection,keys_collection
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

def TGS_execution():
    if len(sys.argv)!=3:
        print(f"Usage:{sys.argv[0]} --listen port")
        exit(1)

    port = int(sys.argv[2])
    listen_sock = create_server(port)
    print(f"Listening on port {port}……")

    sock, addr = listen_sock.accept()

    #接受来自客户的信息
    data=b''
    expected_len=4*MAX_ID_BYTES+KEY_LEN+3*TS_LEN+2*NONCE_LEN
    while len(data)<expected_len:
        data+=sock.recv(4096)

    id_v_received=data[:MAX_ID_BYTES]
    ticket_tgs=data[MAX_ID_BYTES:3*MAX_ID_BYTES+KEY_LEN+2*TS_LEN+NONCE_LEN+MAC_LEN]
    nonce_as_tgs=ticket_tgs[-NONCE_LEN:]
    cipher=ticket_tgs[:-NONCE_LEN]

    key=keys_collection.find_one({'key_name':'tgs_as'})
    k_tgs=key.get('key')
    Ticket_tgs=symmetric_decrypt(nonce_as_tgs,cipher,k_tgs)

    #拿到Ticket_tgs之后开始验证环节
    K_c_tgs=Ticket_tgs[:KEY_LEN]
    id_c=Ticket_tgs[KEY_LEN:KEY_LEN+MAX_ID_BYTES]
    id_tgs_receive=Ticket_tgs[KEY_LEN+MAX_ID_BYTES:KEY_LEN+2*MAX_ID_BYTES]
    ts_2=struct.unpack(">d",Ticket_tgs[KEY_LEN+2*MAX_ID_BYTES:KEY_LEN+2*MAX_ID_BYTES+TS_LEN])[0]
    ls_2=struct.unpack(">d",Ticket_tgs[-TS_LEN:])[0]

    if time.time()-ts_2>ls_2:
        print("票据已过期")
        exit(1)

    #接下来就是验证authenticator是否合法有效
    authenticator_c=data[3*MAX_ID_BYTES+KEY_LEN+2*TS_LEN+NONCE_LEN+MAC_LEN:]
    nonce_auth=authenticator_c[-NONCE_LEN:]
    cipher=authenticator_c[:-NONCE_LEN]

    Authenticator_c=symmetric_decrypt(nonce_auth,cipher,K_c_tgs)
    id_c_received=Authenticator_c[:MAX_ID_BYTES]
    ts_3=struct.unpack(">d",Authenticator_c[MAX_ID_BYTES:])[0]

    if id_c!=id_c_received:
        print("非法持有票据")
        exit(1)

    if time.time()-ts_3>300:
        print("票据已过期")
        exit(1)

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

    ticket=K_c_v+id_c+id_v_received+ts_4_encoded+ls_4_encoded
    nonce_v,ticket_v=symmetric_encrypt(ticket,k_v)
    Ticket_v=ticket_v+nonce_v
    message=K_c_v+id_v_received+ts_4_encoded+Ticket_v

    nonce_tgs_c,m=symmetric_encrypt(message,K_c_tgs)
    sock.sendall(m+nonce_tgs_c)

    sock.close()


if __name__ == "__main__":
    TGS_execution()



