import os
from dotenv import load_dotenv
from pymongo import MongoClient

# 加载环境变量
load_dotenv()

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