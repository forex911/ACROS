import os
import tempfile
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    # Base Configuration
    ENVIRONMENT: str = Field("development", description="Environment mode (development/production)")
    
    # MongoDB Configuration
    MONGO_URI: str = Field("mongodb://localhost:27017", description="MongoDB connection string")
    DATABASE_NAME: str = Field("sentinel_ai", description="MongoDB database name")

    # Directory Configuration
    UPLOAD_DIR: str = Field(
        default=os.path.join(tempfile.gettempdir(), "sentinel_uploads"),
        description="Local temporary upload directory"
    )
    REPORT_DIR: str = Field(
        default=os.path.join(tempfile.gettempdir(), "sentinel_reports"),
        description="Local temporary report directory"
    )

    # Upload Validation Configuration
    ALLOWED_EXTENSIONS: List[str] = Field(
        default=[".py", ".exe", ".js", ".bat"],
        description="Allowed file extensions for upload"
    )
    MAX_UPLOAD_SIZE_BYTES: int = Field(
        default=104857600,  # 100 MB
        description="Maximum file upload size in bytes"
    )

    # Object Storage (S3 / MinIO) Configuration
    S3_ENDPOINT: str = Field(default="http://localhost:9000", description="S3/MinIO endpoint URL")
    S3_REGION: str = Field(default="us-east-1", description="S3 region")
    S3_ACCESS_KEY: str = Field(..., description="S3 access key ID")
    S3_SECRET_KEY: str = Field(..., description="S3 secret access key")
    S3_BUCKET: str = Field("uploads", description="S3 bucket name")
    S3_USE_SSL: bool = Field(False, description="Use SSL for S3 connection")
    S3_PRESIGNED_EXPIRATION: int = Field(300, description="S3 presigned URL expiration in seconds")

    # JWT / Auth Configuration
    SECRET_KEY: str = Field(..., description="JWT Secret Key")
    JWT_ALGORITHM: str = Field("HS256", description="JWT Algorithm")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(15, description="Access token expiration in minutes")
    REFRESH_TOKEN_EXPIRE_DAYS: int = Field(7, description="Refresh token expiration in days")
    API_KEY_HEADER: str = Field("X-API-KEY", description="Header name for API Keys")
    COOKIE_SECURE: bool = Field(False, description="Set Secure flag on cookies (True in production)")

    # Sandbox Configuration
    SANDBOX_MODE: str = Field("mock", description="Sandbox mode: mock | kubernetes | firecracker | kata")
    SANDBOX_RUNTIME: str = Field("gvisor", description="Sandbox runtime: gvisor | kata | firecracker")

    # Neo4j / Graph DB Configuration
    NEO4J_URI: str = Field("bolt://localhost:7687", description="Neo4j connection string")
    NEO4J_USER: str = Field(..., description="Neo4j username")
    NEO4J_PASSWORD: str = Field(..., description="Neo4j password")

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


# Instantiate settings explicitly to fail fast on startup if secrets are missing
settings = Settings()

# Compatibility exports for existing code
MONGO_URI = settings.MONGO_URI
DATABASE_NAME = settings.DATABASE_NAME
UPLOAD_DIR = settings.UPLOAD_DIR
REPORT_DIR = settings.REPORT_DIR
ALLOWED_EXTENSIONS = settings.ALLOWED_EXTENSIONS
S3_ENDPOINT = settings.S3_ENDPOINT
S3_REGION = settings.S3_REGION
S3_ACCESS_KEY = settings.S3_ACCESS_KEY
S3_SECRET_KEY = settings.S3_SECRET_KEY
S3_BUCKET = settings.S3_BUCKET
S3_USE_SSL = settings.S3_USE_SSL
S3_PRESIGNED_EXPIRATION = settings.S3_PRESIGNED_EXPIRATION
SECRET_KEY = settings.SECRET_KEY
ALGORITHM = settings.JWT_ALGORITHM
ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = settings.REFRESH_TOKEN_EXPIRE_DAYS
API_KEY_HEADER = settings.API_KEY_HEADER
COOKIE_SECURE = settings.COOKIE_SECURE
SANDBOX_MODE = settings.SANDBOX_MODE
SANDBOX_RUNTIME = settings.SANDBOX_RUNTIME
NEO4J_URI = settings.NEO4J_URI
NEO4J_USER = settings.NEO4J_USER
NEO4J_PASSWORD = settings.NEO4J_PASSWORD
MAX_UPLOAD_SIZE_BYTES = settings.MAX_UPLOAD_SIZE_BYTES
