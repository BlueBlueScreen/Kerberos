import sys
import socket
import time
import pysodium
import hashlib
import struct
import security
from database import db, users_collection
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


def client_execution():
    if len(sys.argv) != 9:
        print("用法: python脚本名 <username> <password> <AS_IP> <AS_PORT> <TGS_IP> <TGS_PORT> <V_IP> <V_PORT>")
        exit(1)

    username = sys.argv[1]
    password = sys.argv[2]

    # 连接AS服务器
    ip_as = sys.argv[3]
    port_as = int(sys.argv[4])
    sock_as = connect_socket(ip_as, port_as)

    ts_1 = time.time()
    id_tgs = "TGS"
    username_encoded = username.encode()[:MAX_ID_BYTES].ljust(MAX_ID_BYTES, b'\0')
    id_tgs_encoded = id_tgs.encode()[:MAX_ID_BYTES].ljust(MAX_ID_BYTES, b'\0')
    ts_1_encoded = struct.pack('>d', ts_1)  # 使用大端字节序

    sock_as.sendall(username_encoded + id_tgs_encoded + ts_1_encoded)

    data = b''
    expected_len = 2 * KEY_LEN + 3 * MAX_ID_BYTES + 4 * TS_LEN + 2 * NONCE_LEN+2*MAC_LEN
    while len(data) < expected_len:
        data += sock_as.recv(4096)

    cipher_as = data[:-NONCE_LEN]
    nonce_as_c = data[-NONCE_LEN:]

    # 查询用户数据库
    user = users_collection.find_one({'username': username})
    if not user:
        print("用户不存在")
        exit(1)
    password_hash = user.get("password_hash")
    if not password_hash:
        print("用户密码哈希未找到")
        exit(1)
    k = password_hash[16:]  # 假设salt为前16字节

    decrypted_as = symmetric_decrypt(nonce_as_c, cipher_as, k)
    if not decrypted_as:
        print("AS解密失败")
        exit(1)

    # 解析AS响应
    K_c_tgs = decrypted_as[:KEY_LEN]
    id_tgs_received = decrypted_as[KEY_LEN:KEY_LEN + MAX_ID_BYTES].rstrip(b'\0')
    if id_tgs_received != id_tgs.encode():
        print("AS返回的TGS ID不匹配")
        exit(1)

    ts_2 = struct.unpack('>d', decrypted_as[KEY_LEN + MAX_ID_BYTES:KEY_LEN + MAX_ID_BYTES + TS_LEN])[0]
    if abs(time.time() - ts_2) > 300:
        print("AS时间戳过期")
        exit(1)

    Ticket_tgs = decrypted_as[KEY_LEN + MAX_ID_BYTES + 2 * TS_LEN:]
    sock_as.close()
    # 连接TGS服务器
    ip_tgs = sys.argv[5]
    port_tgs = int(sys.argv[6])
    sock_tgs = connect_socket(ip_tgs, port_tgs)

    id_v = "V"
    id_v_encoded = id_v.encode()[:MAX_ID_BYTES].ljust(MAX_ID_BYTES, b'\0')
    ts_3 = time.time()
    ts_3_encoded = struct.pack('>d', ts_3)

    # 构造认证器
    auth_data = username_encoded + ts_3_encoded
    nonce_tgs, auth_encrypted = symmetric_encrypt(auth_data, K_c_tgs)
    Authenticator_1 = auth_encrypted + nonce_tgs
    sock_tgs.sendall(id_v_encoded + Ticket_tgs + Authenticator_1)

    data = b''
    expected_len = 2 * KEY_LEN + 3 * MAX_ID_BYTES + 3 * TS_LEN + 2 * NONCE_LEN+2*MAC_LEN
    while len(data) < expected_len:
        data += sock_tgs.recv(4096)

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
    ip_v = sys.argv[7]
    port_v = int(sys.argv[8])
    sock_v = connect_socket(ip_v, port_v)

    ts_5 = time.time()
    ts_5_encoded = struct.pack('>d', ts_5)

    # 构造最终认证器
    auth_data_v = username_encoded + ts_5_encoded
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

    print("认证成功")
    sock_v.close()


if __name__ == "__main__":
    client_execution()