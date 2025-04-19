from database import db, users_collection
import sys
from pymongo.errors import DuplicateKeyError
import hashlib
import os

def hash_password(password: str) -> bytes:
    """对密码进行 SHA-256 哈希处理，并添加盐"""
    salt = os.urandom(16)  # 生成16字节的随机盐
    # 将盐与密码结合后进行 SHA-256 哈希
    salted_password = salt + password.encode('utf-8')
    hashed_password = hashlib.sha256(salted_password).digest()  # 使用 .digest() 获取二进制哈希值
    return salt + hashed_password  # 返回盐 + 哈希值（共48字节）

def verify_password(password: str, hashed: bytes) -> bool:
    """验证密码是否正确"""
    salt = hashed[:16]  # 提取盐（前16字节）
    stored_hash = hashed[16:]  # 提取存储的哈希值（剩余部分）

    # 重新计算输入密码的哈希值，并与存储的哈希值进行比较
    salted_password = salt + password.encode('utf-8')
    hashed_input = hashlib.sha256(salted_password).digest()  # 获取二进制哈希值
    return stored_hash == hashed_input  # 比较哈希值

def register_user(username: str, password: str):
    """注册用户并保存到数据库中"""
    hashed_password = hash_password(password)  # 使用 SHA-256 哈希
    user_data = {
        "username": username,
        "password_hash": hashed_password
    }
    print(f"密码哈希的长度: {len(hashed_password)}")  # 打印哈希长度，应该是48字节
    try:
        result = users_collection.insert_one(user_data)
        print(f"用户注册成功, 用户ID：{result.inserted_id}")
    except DuplicateKeyError:
        print("用户名已存在，请选择其他用户名")

def find_user_by_username(username: str):
    """根据用户名查询用户信息"""
    user = users_collection.find_one({"username": username})
    return user

def verify_user(username: str, password: str):
    """验证用户登录信息"""
    user = find_user_by_username(username)
    if user and verify_password(password, user["password"]):  # 使用 SHA-256 校验密码
        return True
    return False

def delete_user(username: str):
    """删除用户"""
    result = users_collection.delete_one({"username": username})
    if result.deleted_count > 0:
        print(f"{username} 用户已删除")
    else:
        print(f"{username} 用户未找到")

def main():
    # 检查命令行参数
    if len(sys.argv) != 3:
        print(f"用法: {sys.argv[0]} <用户名> <密码>")
        exit(1)

    username = sys.argv[1]
    password = sys.argv[2]
    # delete_user("Alice")
    register_user(username, password)

if __name__ == "__main__":
    main()
