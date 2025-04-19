import os
from database import keys_collection
import pysodium

def generate_key():
    key=pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
    return key

def delete_user(username: str):
    """删除用户"""
    result = keys_collection.delete_one({"key_name": username})
    if result.deleted_count > 0:
        print(f"{username} 用户已删除")
    else:
        print(f"{username} 用户未找到")

def find_key_by_keyname(keyname: str):
    """根据用户名查询用户信息"""
    key = keys_collection.find_one({"key_name": keyname})
    return key

#生成TGS和AS共享的密钥
TGS_AS=generate_key()
keydata={
    "key_name":"tgs_as",
    "key":TGS_AS
}

#生成TGS和V共享的密钥
keys_collection.insert_one(keydata)
TGS_V=generate_key()
keydata={
    "key_name":"tgs_v",
    "key":TGS_V
}
keys_collection.insert_one(keydata)









