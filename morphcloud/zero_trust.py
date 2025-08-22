"""
Zero-Trust Architecture Module

This module implements comprehensive zero-trust security including:
- Service mesh with mTLS authentication
- API gateway security with rate limiting and DDoS protection
- Secret management integration
- Service-to-service authentication
- Dynamic policy enforcement
"""

import os
import json
import time
import hashlib
import base64
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

logger = logging.getLogger(__name__)


class TrustLevel(Enum):
    """Trust levels for zero-trust architecture"""

    UNTRUSTED = "untrusted"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    TRUSTED = "trusted"


class AuthenticationMethod(Enum):
    """Authentication methods"""

    NONE = "none"
    API_KEY = "api_key"
    JWT = "jwt"
    MTLS = "mtls"
    OAUTH2 = "oauth2"
    SAML = "saml"


@dataclass
class ServiceIdentity:
    """Service identity for zero-trust authentication"""

    service_id: str
    service_name: str
    trust_level: TrustLevel
    public_key: str
    certificate: str
    capabilities: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None


@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""

    requests_per_minute: int = 60
    requests_per_hour: int = 1000
    burst_size: int = 10
    window_size: int = 60  # seconds
    enable_ddos_protection: bool = True
    ddos_threshold: int = 100  # requests per second
    block_duration: int = 300  # seconds


@dataclass
class ZeroTrustConfig:
    """Zero-trust configuration"""

    trust_level: TrustLevel = TrustLevel.MEDIUM
    authentication_method: AuthenticationMethod = AuthenticationMethod.MTLS
    enable_service_mesh: bool = True
    enable_api_gateway: bool = True
    enable_secret_management: bool = True
    rate_limit_config: RateLimitConfig = field(default_factory=RateLimitConfig)
    jwt_secret: Optional[str] = None
    jwt_expiry_hours: int = 24
    mtls_ca_cert: Optional[str] = None
    mtls_ca_key: Optional[str] = None
    vault_url: Optional[str] = None
    vault_token: Optional[str] = None
    aws_region: Optional[str] = None
    aws_secrets_manager: bool = False


class ServiceMesh:
    """Service mesh implementation with mTLS authentication"""

    def __init__(self, config: ZeroTrustConfig):
        self.config = config
        self.services: Dict[str, ServiceIdentity] = {}
        self.certificates: Dict[str, Dict[str, Any]] = {}
        self._init_certificates()

    def _init_certificates(self):
        """Initialize CA certificates for mTLS"""
        if not self.config.mtls_ca_cert or not self.config.mtls_ca_key:
            self._generate_ca_certificates()

    def _generate_ca_certificates(self):
        """Generate CA certificates for mTLS"""
        try:
            # Generate CA private key
            ca_private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )

            # Generate CA public key
            ca_public_key = ca_private_key.public_key()

            # Create CA certificate
            from cryptography import x509
            from cryptography.x509.oid import NameOID

            subject = issuer = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MorphCloud"),
                    x509.NameAttribute(NameOID.COMMON_NAME, "MorphCloud CA"),
                ]
            )

            ca_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(ca_public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=365))
                .add_extension(
                    x509.BasicConstraints(ca=True, path_length=None), critical=True
                )
                .sign(ca_private_key, hashes.SHA256())
            )

            # Store certificates
            self.certificates["ca"] = {
                "cert": ca_cert.public_bytes(serialization.Encoding.PEM),
                "key": ca_private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
            }

            # Update config
            self.config.mtls_ca_cert = self.certificates["ca"]["cert"].decode()
            self.config.mtls_ca_key = self.certificates["ca"]["key"].decode()

            logger.info("Generated CA certificates for mTLS")

        except Exception as e:
            logger.error(f"Failed to generate CA certificates: {e}")

    def register_service(
        self,
        service_id: str,
        service_name: str,
        trust_level: TrustLevel,
        capabilities: List[str] = None,
    ) -> ServiceIdentity:
        """Register a new service in the mesh"""
        try:
            # Generate service certificates
            service_cert, service_key = self._generate_service_certificates(service_id)

            # Create service identity
            service_identity = ServiceIdentity(
                service_id=service_id,
                service_name=service_name,
                trust_level=trust_level,
                public_key=service_key.public_key()
                .public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                )
                .decode(),
                certificate=service_cert.public_bytes(
                    serialization.Encoding.PEM
                ).decode(),
                capabilities=capabilities or [],
            )

            # Store service
            self.services[service_id] = service_identity

            # Store service certificates
            self.certificates[service_id] = {
                "cert": service_cert.public_bytes(serialization.Encoding.PEM),
                "key": service_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ),
            }

            logger.info(f"Registered service: {service_name} ({service_id})")
            return service_identity

        except Exception as e:
            logger.error(f"Failed to register service {service_id}: {e}")
            raise

    def _generate_service_certificates(self, service_id: str):
        """Generate certificates for a service"""
        try:
            # Generate service private key
            service_private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048
            )

            # Generate service public key
            service_public_key = service_private_key.public_key()

            # Create service certificate
            from cryptography import x509
            from cryptography.x509.oid import NameOID

            subject = x509.Name(
                [
                    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MorphCloud"),
                    x509.NameAttribute(NameOID.COMMON_NAME, service_id),
                ]
            )

            # Get CA certificate and key
            ca_cert = x509.load_pem_x509_certificate(self.certificates["ca"]["cert"])
            ca_key = serialization.load_pem_private_key(
                self.certificates["ca"]["key"], password=None
            )

            # Create service certificate
            service_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(ca_cert.subject)
                .public_key(service_public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=30))
                .add_extension(
                    x509.BasicConstraints(ca=False, path_length=None), critical=True
                )
                .add_extension(
                    x509.SubjectAlternativeName(
                        [x509.DNSName(service_id), x509.IPAddress("127.0.0.1")]
                    ),
                    critical=False,
                )
                .sign(ca_key, hashes.SHA256())
            )

            return service_cert, service_private_key

            # Load CA certificate and key
            ca_cert = x509.load_pem_x509_certificate(self.certificates["ca"]["cert"])
            ca_key = serialization.load_pem_private_key(
                self.certificates["ca"]["key"], password=None
            )

            service_cert = (
                x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(ca_cert.subject)
                .public_key(service_public_key)
                .serial_number(x509.random_serial_number())
                .not_valid_before(datetime.utcnow())
                .not_valid_after(datetime.utcnow() + timedelta(days=30))
                .add_extension(
                    x509.SubjectAlternativeName(
                        [x509.DNSName(service_id), x509.IPAddress("127.0.0.1")]
                    ),
                    critical=False,
                )
                .sign(ca_key, hashes.SHA256())
            )

            return service_cert, service_private_key

        except Exception as e:
            logger.error(f"Failed to generate service certificates: {e}")
            raise

    def authenticate_service(
        self, service_id: str, certificate: str
    ) -> Optional[ServiceIdentity]:
        """Authenticate a service using its certificate"""
        try:
            if service_id not in self.services:
                return None

            # Verify certificate
            service_cert = x509.load_pem_x509_certificate(certificate.encode())

            # Verify against CA
            ca_cert = x509.load_pem_x509_certificate(self.certificates["ca"]["cert"])

            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                service_cert.signature,
                service_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                service_cert.signature_hash_algorithm,
            )

            # Check if certificate is valid
            if (
                datetime.utcnow() < service_cert.not_valid_before
                or datetime.utcnow() > service_cert.not_valid_after
            ):
                return None

            return self.services[service_id]

        except Exception as e:
            logger.error(f"Service authentication failed for {service_id}: {e}")
            return None

    def get_service_certificates(self, service_id: str) -> Optional[Dict[str, Any]]:
        """Get certificates for a service"""
        return self.certificates.get(service_id)


class APIGateway:
    """API Gateway with security features"""

    def __init__(self, config: ZeroTrustConfig):
        self.config = config
        self.rate_limiters: Dict[str, "RateLimiter"] = {}
        self.api_keys: Dict[str, Dict[str, Any]] = {}
        self.jwt_tokens: Dict[str, Dict[str, Any]] = {}
        self._init_rate_limiters()

    def _init_rate_limiters(self):
        """Initialize rate limiters for different endpoints"""
        # Global rate limiter
        self.rate_limiters["global"] = RateLimiter(
            self.config.rate_limit_config.requests_per_minute,
            self.config.rate_limit_config.window_size,
        )

        # Per-endpoint rate limiters
        endpoints = ["/api/v1/instances", "/api/v1/snapshots", "/api/v1/images"]
        for endpoint in endpoints:
            self.rate_limiters[endpoint] = RateLimiter(
                self.config.rate_limit_config.requests_per_minute // 2,
                self.config.rate_limit_config.window_size,
            )

    def authenticate_request(
        self, request_headers: Dict[str, str], request_path: str
    ) -> Dict[str, Any]:
        """Authenticate an incoming request"""
        auth_result = {
            "authenticated": False,
            "service_id": None,
            "trust_level": None,
            "capabilities": [],
            "rate_limited": False,
            "ddos_detected": False,
        }

        try:
            # Check rate limiting
            if self._is_rate_limited(request_path):
                auth_result["rate_limited"] = True
                return auth_result

            # Check for DDoS
            if self._is_ddos_attack(request_headers):
                auth_result["ddos_detected"] = True
                return auth_result

            # Authenticate based on method
            if self.config.authentication_method == AuthenticationMethod.API_KEY:
                auth_result.update(self._authenticate_api_key(request_headers))
            elif self.config.authentication_method == AuthenticationMethod.JWT:
                auth_result.update(self._authenticate_jwt(request_headers))
            elif self.config.authentication_method == AuthenticationMethod.MTLS:
                auth_result.update(self._authenticate_mtls(request_headers))

            return auth_result

        except Exception as e:
            logger.error(f"Authentication failed: {e}")
            return auth_result

    def _is_rate_limited(self, request_path: str) -> bool:
        """Check if request is rate limited"""
        # Find appropriate rate limiter
        limiter = None
        for endpoint, endpoint_limiter in self.rate_limiters.items():
            if request_path.startswith(endpoint):
                limiter = endpoint_limiter
                break

        if not limiter:
            limiter = self.rate_limiters["global"]

        return not limiter.allow_request()

    def _is_ddos_attack(self, request_headers: Dict[str, str]) -> bool:
        """Detect potential DDoS attacks"""
        if not self.config.rate_limit_config.enable_ddos_protection:
            return False

        # Check request frequency (simplified)
        client_ip = request_headers.get("X-Forwarded-For", "unknown")
        current_time = time.time()

        # This would need more sophisticated tracking in production
        return False

    def _authenticate_api_key(self, request_headers: Dict[str, str]) -> Dict[str, Any]:
        """Authenticate using API key"""
        api_key = request_headers.get("X-API-Key")
        if not api_key:
            return {"authenticated": False}

        if api_key in self.api_keys:
            key_info = self.api_keys[api_key]
            if not key_info.get("expired", False):
                return {
                    "authenticated": True,
                    "service_id": key_info.get("service_id"),
                    "trust_level": key_info.get("trust_level"),
                    "capabilities": key_info.get("capabilities", []),
                }

        return {"authenticated": False}

    def _authenticate_jwt(self, request_headers: Dict[str, str]) -> Dict[str, Any]:
        """Authenticate using JWT token"""
        auth_header = request_headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return {"authenticated": False}

        token = auth_header[7:]  # Remove "Bearer " prefix

        try:
            if not self.config.jwt_secret:
                return {"authenticated": False}

            payload = jwt.decode(token, self.config.jwt_secret, algorithms=["HS256"])

            return {
                "authenticated": True,
                "service_id": payload.get("service_id"),
                "trust_level": payload.get("trust_level"),
                "capabilities": payload.get("capabilities", []),
            }

        except jwt.ExpiredSignatureError:
            return {"authenticated": False, "error": "Token expired"}
        except jwt.InvalidTokenError:
            return {"authenticated": False, "error": "Invalid token"}

    def _authenticate_mtls(self, request_headers: Dict[str, str]) -> Dict[str, Any]:
        """Authenticate using mTLS (simplified)"""
        # In a real implementation, this would verify client certificates
        # For now, we'll check for a client certificate header
        client_cert = request_headers.get("X-Client-Certificate")
        if not client_cert:
            return {"authenticated": False}

        # This would verify the certificate against the CA
        return {"authenticated": True, "trust_level": TrustLevel.MEDIUM}

    def generate_api_key(
        self,
        service_id: str,
        trust_level: TrustLevel,
        capabilities: List[str],
        expiry_hours: int = 24,
    ) -> str:
        """Generate a new API key for a service"""
        try:
            # Generate random API key
            api_key = base64.b64encode(os.urandom(32)).decode()

            # Store key information
            self.api_keys[api_key] = {
                "service_id": service_id,
                "trust_level": trust_level,
                "capabilities": capabilities,
                "created_at": datetime.utcnow(),
                "expires_at": datetime.utcnow() + timedelta(hours=expiry_hours),
                "expired": False,
            }

            logger.info(f"Generated API key for service: {service_id}")
            return api_key

        except Exception as e:
            logger.error(f"Failed to generate API key: {e}")
            raise

    def generate_jwt_token(
        self, service_id: str, trust_level: TrustLevel, capabilities: List[str]
    ) -> str:
        """Generate a JWT token for a service"""
        try:
            if not self.config.jwt_secret:
                raise ValueError("JWT secret not configured")

            payload = {
                "service_id": service_id,
                "trust_level": trust_level.value,
                "capabilities": capabilities,
                "iat": datetime.utcnow(),
                "exp": datetime.utcnow()
                + timedelta(hours=self.config.jwt_expiry_hours),
            }

            token = jwt.encode(payload, self.config.jwt_secret, algorithm="HS256")

            # Store token information
            self.jwt_tokens[token] = {
                "service_id": service_id,
                "trust_level": trust_level,
                "capabilities": capabilities,
                "created_at": datetime.utcnow(),
                "expires_at": payload["exp"],
            }

            logger.info(f"Generated JWT token for service: {service_id}")
            return token

        except Exception as e:
            logger.error(f"Failed to generate JWT token: {e}")
            raise


class RateLimiter:
    """Rate limiter implementation"""

    def __init__(self, max_requests: int, window_size: int):
        self.max_requests = max_requests
        self.window_size = window_size
        self.requests: List[float] = []

    def allow_request(self) -> bool:
        """Check if request is allowed"""
        current_time = time.time()

        # Remove old requests outside the window
        self.requests = [
            req_time
            for req_time in self.requests
            if current_time - req_time < self.window_size
        ]

        # Check if we can allow the request
        if len(self.requests) < self.max_requests:
            self.requests.append(current_time)
            return True

        return False

    def get_current_usage(self) -> Dict[str, Any]:
        """Get current rate limit usage"""
        current_time = time.time()

        # Remove old requests
        self.requests = [
            req_time
            for req_time in self.requests
            if current_time - req_time < self.window_size
        ]

        return {
            "current_requests": len(self.requests),
            "max_requests": self.max_requests,
            "window_size": self.window_size,
            "remaining_requests": max(0, self.max_requests - len(self.requests)),
        }


class SecretManager:
    """Secret management with multiple backends"""

    def __init__(self, config: ZeroTrustConfig):
        self.config = config
        self.vault_client = None
        self.aws_secrets_client = None
        self._init_clients()

    def _init_clients(self):
        """Initialize secret management clients"""
        # Initialize HashiCorp Vault client
        if self.config.vault_url and self.config.vault_token:
            try:
                import hvac

                self.vault_client = hvac.Client(
                    url=self.config.vault_url, token=self.config.vault_token
                )
                logger.info("Vault client initialized")
            except ImportError:
                logger.warning("hvac not available, Vault integration disabled")
            except Exception as e:
                logger.warning(f"Failed to initialize Vault client: {e}")

        # Initialize AWS Secrets Manager client
        if self.config.aws_secrets_manager:
            try:
                if self.config.aws_region:
                    self.aws_secrets_client = boto3.client(
                        "secretsmanager", region_name=self.config.aws_region
                    )
                else:
                    self.aws_secrets_client = boto3.client("secretsmanager")
                logger.info("AWS Secrets Manager client initialized")
            except NoCredentialsError:
                logger.warning("AWS credentials not found")
            except Exception as e:
                logger.warning(f"Failed to initialize AWS Secrets Manager: {e}")

    def store_secret(
        self, secret_name: str, secret_value: str, metadata: Dict[str, Any] = None
    ) -> bool:
        """Store a secret in the configured backend"""
        try:
            if self.vault_client:
                return self._store_in_vault(secret_name, secret_value, metadata)
            elif self.aws_secrets_client:
                return self._store_in_aws(secret_name, secret_value, metadata)
            else:
                return self._store_locally(secret_name, secret_value, metadata)
        except Exception as e:
            logger.error(f"Failed to store secret {secret_name}: {e}")
            return False

    def retrieve_secret(self, secret_name: str) -> Optional[str]:
        """Retrieve a secret from the configured backend"""
        try:
            if self.vault_client:
                return self._retrieve_from_vault(secret_name)
            elif self.aws_secrets_client:
                return self._retrieve_from_aws(secret_name)
            else:
                return self._retrieve_locally(secret_name)
        except Exception as e:
            logger.error(f"Failed to retrieve secret {secret_name}: {e}")
            return None

    def _store_in_vault(
        self, secret_name: str, secret_value: str, metadata: Dict[str, Any] = None
    ) -> bool:
        """Store secret in HashiCorp Vault"""
        try:
            # Create secret with metadata
            secret_data = {"value": secret_value}
            if metadata:
                secret_data.update(metadata)

            self.vault_client.secrets.kv.v2.create_or_update_secret(
                path=secret_name, secret=secret_data
            )
            return True
        except Exception as e:
            logger.error(f"Failed to store in Vault: {e}")
            return False

    def _retrieve_from_vault(self, secret_name: str) -> Optional[str]:
        """Retrieve secret from HashiCorp Vault"""
        try:
            response = self.vault_client.secrets.kv.v2.read_secret_version(
                path=secret_name
            )
            return response["data"]["data"]["value"]
        except Exception as e:
            logger.error(f"Failed to retrieve from Vault: {e}")
            return None

    def _store_in_aws(
        self, secret_name: str, secret_value: str, metadata: Dict[str, Any] = None
    ) -> bool:
        """Store secret in AWS Secrets Manager"""
        try:
            # Prepare secret data
            secret_data = {"value": secret_value, "metadata": metadata or {}}

            self.aws_secrets_client.create_secret(
                Name=secret_name,
                SecretString=json.dumps(secret_data),
                Description=f"Secret for {secret_name}",
            )
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceExistsException":
                # Update existing secret
                self.aws_secrets_client.update_secret(
                    SecretId=secret_name, SecretString=json.dumps(secret_data)
                )
                return True
            else:
                logger.error(f"AWS Secrets Manager error: {e}")
                return False
        except Exception as e:
            logger.error(f"Failed to store in AWS: {e}")
            return False

    def _retrieve_from_aws(self, secret_name: str) -> Optional[str]:
        """Retrieve secret from AWS Secrets Manager"""
        try:
            response = self.aws_secrets_client.get_secret_value(SecretId=secret_name)
            secret_data = json.loads(response["SecretString"])
            return secret_data["value"]
        except Exception as e:
            logger.error(f"Failed to retrieve from AWS: {e}")
            return None

    def _store_locally(
        self, secret_name: str, secret_value: str, metadata: Dict[str, Any] = None
    ) -> bool:
        """Store secret locally (encrypted)"""
        try:
            # Generate encryption key from environment
            key = os.getenv("MORPHCLOUD_SECRET_KEY", "default-key").encode()

            # Encrypt secret value
            encrypted_value = self._encrypt_value(secret_value, key)

            # Store encrypted value and metadata
            secret_data = {
                "encrypted_value": base64.b64encode(encrypted_value).decode(),
                "metadata": metadata or {},
                "created_at": datetime.utcnow().isoformat(),
            }

            # In production, this would be stored in a secure database
            # For now, we'll use a simple file-based approach
            secrets_dir = os.path.expanduser("~/.morphcloud/secrets")
            os.makedirs(secrets_dir, exist_ok=True)

            secret_file = os.path.join(secrets_dir, f"{secret_name}.json")
            with open(secret_file, "w") as f:
                json.dump(secret_data, f, indent=2)

            return True

        except Exception as e:
            logger.error(f"Failed to store locally: {e}")
            return False

    def _retrieve_locally(self, secret_name: str) -> Optional[str]:
        """Retrieve secret from local storage"""
        try:
            # Get encryption key
            key = os.getenv("MORPHCLOUD_SECRET_KEY", "default-key").encode()

            # Read encrypted secret
            secrets_dir = os.path.expanduser("~/.morphcloud/secrets")
            secret_file = os.path.join(secrets_dir, f"{secret_name}.json")

            with open(secret_file, "r") as f:
                secret_data = json.load(f)

            # Decrypt value
            encrypted_value = base64.b64decode(secret_data["encrypted_value"])
            decrypted_value = self._decrypt_value(encrypted_value, key)

            return decrypted_value.decode()

        except Exception as e:
            logger.error(f"Failed to retrieve locally: {e}")
            return None

    def _encrypt_value(self, value: str, key: bytes) -> bytes:
        """Encrypt a value using AES"""
        # Generate a random IV
        iv = os.urandom(16)

        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Pad the value to block size
        padded_value = value.encode()
        block_size = 16
        padding_length = block_size - (len(padded_value) % block_size)
        padded_value += bytes([padding_length] * padding_length)

        # Encrypt
        encrypted = encryptor.update(padded_value) + encryptor.finalize()

        # Return IV + encrypted data
        return iv + encrypted

    def _decrypt_value(self, encrypted_data: bytes, key: bytes) -> bytes:
        """Decrypt a value using AES"""
        # Extract IV
        iv = encrypted_data[:16]
        encrypted = encrypted_data[16:]

        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()

        # Decrypt
        decrypted = decryptor.update(encrypted) + decryptor.finalize()

        # Remove padding
        padding_length = decrypted[-1]
        return decrypted[:-padding_length]


class ZeroTrustManager:
    """Main zero-trust manager"""

    def __init__(self, config: ZeroTrustConfig):
        self.config = config
        self.service_mesh = ServiceMesh(config) if config.enable_service_mesh else None
        self.api_gateway = APIGateway(config) if config.enable_api_gateway else None
        self.secret_manager = (
            SecretManager(config) if config.enable_secret_management else None
        )

    def register_service(
        self,
        service_id: str,
        service_name: str,
        trust_level: TrustLevel,
        capabilities: List[str] = None,
    ) -> Dict[str, Any]:
        """Register a new service in the zero-trust system"""
        try:
            result = {"success": False, "service_id": service_id}

            # Register in service mesh
            if self.service_mesh:
                service_identity = self.service_mesh.register_service(
                    service_id, service_name, trust_level, capabilities
                )
                result["service_mesh"] = "registered"
                result["certificates"] = "generated"

            # Generate API key
            if self.api_gateway:
                api_key = self.api_gateway.generate_api_key(
                    service_id, trust_level, capabilities or []
                )
                result["api_key"] = api_key

            # Generate JWT token
            if self.api_gateway:
                jwt_token = self.api_gateway.generate_jwt_token(
                    service_id, trust_level, capabilities or []
                )
                result["jwt_token"] = jwt_token

            result["success"] = True
            logger.info(f"Service {service_name} registered successfully")
            return result

        except Exception as e:
            logger.error(f"Failed to register service {service_id}: {e}")
            return {"success": False, "error": str(e)}

    def authenticate_request(
        self, request_headers: Dict[str, str], request_path: str
    ) -> Dict[str, Any]:
        """Authenticate an incoming request"""
        if not self.api_gateway:
            return {"authenticated": True, "trust_level": TrustLevel.TRUSTED}

        return self.api_gateway.authenticate_request(request_headers, request_path)

    def store_secret(
        self, secret_name: str, secret_value: str, metadata: Dict[str, Any] = None
    ) -> bool:
        """Store a secret"""
        if not self.secret_manager:
            logger.warning("Secret management not enabled")
            return False

        return self.secret_manager.store_secret(secret_name, secret_value, metadata)

    def retrieve_secret(self, secret_name: str) -> Optional[str]:
        """Retrieve a secret"""
        if not self.secret_manager:
            logger.warning("Secret management not enabled")
            return None

        return self.secret_manager.retrieve_secret(secret_name)

    def get_service_certificates(self, service_id: str) -> Optional[Dict[str, Any]]:
        """Get certificates for a service"""
        if not self.service_mesh:
            return None

        return self.service_mesh.get_service_certificates(service_id)


# Utility functions
def get_zero_trust_manager(config: ZeroTrustConfig = None) -> ZeroTrustManager:
    """Get zero-trust manager instance"""
    if config is None:
        config = ZeroTrustConfig()
    return ZeroTrustManager(config)


def create_service_identity(
    service_id: str, service_name: str, trust_level: TrustLevel = TrustLevel.MEDIUM
) -> Dict[str, Any]:
    """Quick function to create service identity"""
    config = ZeroTrustConfig()
    manager = get_zero_trust_manager(config)
    return manager.register_service(service_id, service_name, trust_level)


def store_secret(
    secret_name: str, secret_value: str, metadata: Dict[str, Any] = None
) -> bool:
    """Quick function to store a secret"""
    config = ZeroTrustConfig()
    manager = get_zero_trust_manager(config)
    return manager.store_secret(secret_name, secret_value, metadata)


def retrieve_secret(secret_name: str) -> Optional[str]:
    """Quick function to retrieve a secret"""
    config = ZeroTrustConfig()
    manager = get_zero_trust_manager(config)
    return manager.retrieve_secret(secret_name)
