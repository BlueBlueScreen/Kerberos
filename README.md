# Kerberos
这是一个对Kerberos协议的简单模拟。我们同时模拟了针对Kerberos协议常见的黄金票据攻击和白银票据攻击

## 项目内容
1. 创建数据库，存储用户注册信息
1. 模拟KDC的运行，实现认证服务器（AS）与票据服务器（TGS）共享密钥，TGS与服务服务器（V）共享密钥
1. 实现客户代码的运行逻辑
1. 实现AS代码的运行逻辑
1. 实现TGS代码的运行逻辑
1. 实现V的运行逻辑
1. 模拟黄金票据攻击
2. 模拟白银票据攻击

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
代码实现可见[client.py](https://github.com/BlueBlueScreen/Kerberos/blob/main/Kerberos/client.py)

### 模拟认证服务器逻辑
AS监听目标端口，接受来自客户的信息。确认客户身份，生成票据，再给客户相应反馈
代码实现[AS.py]（https://github.com/BlueBlueScreen/Kerberos/blob/main/Kerberos/AS.py）

### 模拟票据服务器逻辑
TGS监听目标端口，接受来自客户的信息。确认客户身份，生成票据，再给客户相应反馈
代码实现[TGS.py](https://github.com/BlueBlueScreen/Kerberos/blob/main/Kerberos/TGS.py)

### 模拟服务服务器逻辑
V监听目标端口，接受来自客户的信息。确认客户身份，生成票据，再给客户相应反馈
代码实现[V.py](https://github.com/BlueBlueScreen/Kerberos/blob/main/Kerberos/V.py)

### 进行黄金票据攻击
进行黄金票据攻击的原理是敌手拿到AS与TGS的共享密钥。在此之后敌手可以绕过AS生成任何用户的合法票据，通过TGS的验证，进而通过V的验证获取服务。
通过黄金票据攻击，敌手理论上可以获得管理员级别的权限。

```
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
```
在黄金票据攻击中，敌手会生成一切正常用户交互与AS交互应获得的信息。因此，对后续的TGS与V来说，敌手即为其票据中记录身份的正常用户。因此可完成后续的完整认证流程

### 进行白银票据攻击
白银票据攻击的原理和黄金票据的原理相似，区别是敌手拿到的是TGS与V的共享密钥，此时敌手可以直接绕过AS，TGS与V完成认证。
通过白银票据攻击，敌手同样可以获得管理员级别的权限
```
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
```
如上，敌手在攻破KDC拿到TGS与V的共享密钥后即可自己生成合法的Ticket



