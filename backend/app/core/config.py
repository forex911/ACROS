from dotenv import load_dotenv
import os

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")

import tempfile
UPLOAD_DIR = os.path.join(tempfile.gettempdir(), "sentinel_uploads")
REPORT_DIR = os.path.join(tempfile.gettempdir(), "sentinel_reports")

ALLOWED_EXTENSIONS = [
    ".py",
    ".exe",
    ".js",
    ".bat"
]

# Object storage (S3 / MinIO) configuration
S3_ENDPOINT = os.getenv('S3_ENDPOINT')  # e.g. http://minio:9000
S3_REGION = os.getenv('S3_REGION', 'us-east-1')
S3_ACCESS_KEY = os.getenv('S3_ACCESS_KEY')
S3_SECRET_KEY = os.getenv('S3_SECRET_KEY')
S3_BUCKET = os.getenv('S3_BUCKET', 'uploads')
S3_USE_SSL = os.getenv('S3_USE_SSL', 'false').lower() in ('1', 'true', 'yes')
S3_PRESIGNED_EXPIRATION = int(os.getenv('S3_PRESIGNED_EXPIRATION', '300'))

# JWT / Auth
SECRET_KEY = os.getenv('SECRET_KEY', 'replace-this-with-secure-random')
ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', '15'))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv('REFRESH_TOKEN_EXPIRE_DAYS', '7'))

# API key settings
API_KEY_HEADER = os.getenv('API_KEY_HEADER', 'X-API-KEY')

# Neo4j / Graph DB
NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD', 'neo4j')