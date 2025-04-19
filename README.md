# Kerberos
这是一个对Kerberos协议的简单模拟。我们同时模拟了针对Kerberos协议常见的黄金票据攻击和白银票据攻击

## 项目内容
1. 创建数据库，存储用户注册信息
1. 模拟KDC的运行，实现认证服务器（AS）与票据服务器（TGS）共享密钥，TGS与服务服务器（V）共享密钥
1. 实现客户代码的运行逻辑
1. 实现AS代码的运行逻辑
1. 实现TGS代码的运行逻辑
1. 实现V的运行逻辑
1. 模拟黄金票据攻击，模拟白银票据攻击

## 步骤
### 创建数据库，实现用户注册功能
我们选择使用Mongo数据库来存储用户的注册信息。在本地搭建数据库后，我们创建`users_collection`库来存储用户信息
```
# 获取配置
MONGO_URI = os.getenv("MONGO_URI")
DB_NAME = os.getenv("DB_NAME")

# 连接 MongoDB
client = MongoClient(MONGO_URI)
db = client[DB_NAME]
users_collection=db["users"]
keys_collection=db["keys"]

# 检查连接是否成功
try:
    client.admin.command('ping')
    print("✅ Successfully connected to MongoDB!")
except Exception as e:
    print("❌ MongoDB connection failed:", e)
```
> 我们在本项目中通过数据库操作来模拟服务器间预共享密钥，`keys_collection`完成该功能

用户注册时，提供自己的用户名和口令，我们在此使用python中提供的`os,hashlib`库提供的盐值生成函数和`sha256`哈希函数来实现口令哈希，最终我们将用户名，口令的盐值+哈希值及用户序号存储在数据库中。通过引入`DuplicateKeyError `来防止用户的重复注册

```
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
```

### 模拟KDC的运行
我们通过`pysodium`库提供的函数来随机生成32字节（256位）的密钥
```
def generate_key():
    key=pysodium.randombytes(pysodium.crypto_secretbox_KEYBYTES)
    return key
```
生成后手动添加共享密钥逻辑，以下为TGS和V共享密钥的代码示例
```
#生成TGS和V共享的密钥
keys_collection.insert_one(keydata)
TGS_V=generate_key()
keydata={
    "key_name":"tgs_v",
    "key":TGS_V
}
keys_collection.insert_one(keydata)
```

### 模拟客户端逻辑
我们通过`pysodium`库提供的对称加密函数来充当Kerberos协议中的对称加密模块，使用TCP连接来完成信息的交换。
在接收到服务器的响应后，解密必要数据，解析数据，对时间戳，票据有效期等信息进行验证，之后与下一个服务器进行交互。
具体代码实现可见


