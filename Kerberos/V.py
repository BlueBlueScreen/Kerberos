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

def V_execution():
    if len(sys.argv)!=3:
        print(f"Usage:{sys.argv[0]} --listen port")
        exit(1)

    port = int(sys.argv[2])
    listen_sock = create_server(port)
    print(f"Listening on port {port}……")

    sock, addr = listen_sock.accept()
    print("连接客户进程")
    id_v='V'.encode()[:MAX_ID_BYTES].ljust(MAX_ID_BYTES,b'\0')
    #接受来自客户的信息
    data=b''
    expected_len=3*MAX_ID_BYTES+KEY_LEN+3*TS_LEN+2*NONCE_LEN+2*MAC_LEN
    while len(data)<expected_len:
        data+=sock.recv(4096)


    ticket=data[:KEY_LEN+2*MAX_ID_BYTES+2*TS_LEN+MAC_LEN]
    nonce_ticket=data[KEY_LEN+2*MAX_ID_BYTES+2*TS_LEN+MAC_LEN:KEY_LEN+2*MAX_ID_BYTES+2*TS_LEN+MAC_LEN+NONCE_LEN]
    key=keys_collection.find_one({"key_name":"tgs_v"})
    k=key.get("key")

    Ticket_v=symmetric_decrypt(nonce_ticket,ticket,k)

    #提取出票据信息后，检测票据是否有效
    K_c_v=Ticket_v[:KEY_LEN]
    id_c=Ticket_v[KEY_LEN:KEY_LEN+MAX_ID_BYTES]
    id_v_received=Ticket_v[KEY_LEN+MAX_ID_BYTES:KEY_LEN+2*MAX_ID_BYTES]
    ts_4=struct.unpack('>d',Ticket_v[KEY_LEN+2*MAX_ID_BYTES:KEY_LEN+2*MAX_ID_BYTES+TS_LEN])[0]
    ls_4=struct.unpack('>d',Ticket_v[-TS_LEN:])[0]

    print("检查票据")
    if id_v_received!=id_v:
        print("票据不属于该服务器服务器范围内")
        exit(1)

    if time.time()-ts_4>ls_4:
        print("票据已过期")
        exit(1)

    authenticator_c=data[KEY_LEN+2*MAX_ID_BYTES+2*TS_LEN+NONCE_LEN+MAC_LEN:]
    nonce_2=authenticator_c[-NONCE_LEN:]
    cipher=authenticator_c[:-NONCE_LEN]

    Authenticator_c=symmetric_decrypt(nonce_2,cipher,K_c_v)
    id_c_received=Authenticator_c[:MAX_ID_BYTES]
    ts_5=struct.unpack('>d',Authenticator_c[-TS_LEN:])[0]

    if time.time()-ts_5>300:
        print("票据失效")
        exit(1)

    if id_c.rstrip(b'\x00') != id_c_received.rstrip(b'\x00'):
        print("客户端身份不一致")
        exit(1)

    resp = struct.pack(">d", ts_5 + 1)  # 使用双精度浮点格式
    sock.sendall(resp)

    sock.close()


if __name__ == "__main__":
    V_execution()



