import datetime
import os
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID

CA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'ca')
CA_KEY_PATH = os.path.join(CA_DIR, 'ca_private_key.pem')
CA_CERT_PATH = os.path.join(CA_DIR, 'ca_cert.pem')

def init_ca():
    """Initializes the Certificate Authority root key and self-signed certificate if they don't exist."""
    if not os.path.exists(CA_DIR):
        os.makedirs(CA_DIR)
        
    if os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH):
        with open(CA_KEY_PATH, 'rb') as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(CA_CERT_PATH, 'rb') as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        return ca_key, ca_cert

    # Generate Root CA private key
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    # Save CA private key
    with open(CA_KEY_PATH, 'wb') as f:
        f.write(ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
        
    # Generate self-signed Root Certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "KP"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Kohat"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SigNet CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SigNet Root CA"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow() - datetime.timedelta(days=1)
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256())
    
    # Save CA root certificate
    with open(CA_CERT_PATH, 'wb') as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
        
    return ca_key, ca_cert

def generate_user_keypair():
    """Generates an RSA-2048 private/public key pair."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

def encrypt_private_key(private_key, password):
    """Encrypts the private key using AES-256 via password-based PKCS8 serialization."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode('utf-8'))
    )
    return pem.decode('utf-8')

def decrypt_private_key(encrypted_pem_str, password):
    """Decrypts the private key using password."""
    return serialization.load_pem_private_key(
        encrypted_pem_str.encode('utf-8'),
        password=password.encode('utf-8')
    )

def get_public_key_pem(private_key):
    """Gets public key PEM bytes from private key."""
    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def get_public_key_fingerprint(public_key_pem):
    """Generates SHA-256 fingerprint from public key PEM."""
    pub_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    der = pub_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashes.Hash(hashes.SHA256())
    digest.update(der)
    fp_bytes = digest.finalize()
    return ":".join(f"{b:02X}" for b in fp_bytes)

def issue_user_certificate(username, email, user_public_key):
    """Issues an X.509 certificate for a user signed by the Root CA."""
    ca_key, ca_cert = init_ca()
    
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "KP"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Kohat"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SigNet Users"),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
    ])
    
    user_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        user_public_key
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow() - datetime.timedelta(days=1)
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)  # 1 year
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True
    ).sign(ca_key, hashes.SHA256())
    
    return user_cert.public_bytes(serialization.Encoding.PEM).decode('utf-8')

def get_message_payload(sender, recipient, subject, body, timestamp_str):
    """Constructs the exact string payload to sign/verify."""
    body_normalized = body.replace('\r\n', '\n').replace('\r', '\n')
    return f"Sender: {sender}\nRecipient: {recipient}\nSubject: {subject}\nBody: {body_normalized}\nTimestamp: {timestamp_str}"

def sign_message(private_key, payload_str):
    """Signs message payload with the sender's private key."""
    signature = private_key.sign(
        payload_str.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_message_signature(sender_certificate_pem, payload_str, signature_b64):
    """Verifies the email signature against the sender certificate and Root CA."""
    try:
        # 1. Load CA certificate
        _, ca_cert = init_ca()
        
        # 2. Load Sender Certificate
        sender_cert = x509.load_pem_x509_certificate(sender_certificate_pem.encode('utf-8'))
        
        # 3. Verify Certificate Signature against CA Public Key
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            sender_cert.signature,
            sender_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            sender_cert.signature_hash_algorithm
        )
        
        # 4. Check certificate expiration (simulation matches UTC)
        now = datetime.datetime.utcnow()
        if now < sender_cert.not_valid_before or now > sender_cert.not_valid_after:
            return False, "Certificate has expired or is not yet valid"
            
        # 5. Verify signature using public key from certificate
        sender_public_key = sender_cert.public_key()
        signature_bytes = base64.b64decode(signature_b64.encode('utf-8'))
        
        sender_public_key.verify(
            signature_bytes,
            payload_str.encode('utf-8'),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        return True, "Signature and certificate verified successfully"
    except Exception as e:
        return False, str(e)
