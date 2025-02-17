from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from jose import jwt
import time
import base64
import json
from typing import Dict, List, Optional
from datetime import datetime, timedelta

app = FastAPI()

# Store for our key pairs
keys: List[Dict] = []

def generate_key_pair(expiry_hours: int = 24) -> Dict:
    """Generate a new RSA key pair with expiry"""
    # Generate private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Get public key
    public_key = private_key.public_key()
    
    # Generate key ID (kid) - using timestamp for simplicity
    kid = str(int(time.time()))
    
    # Calculate expiry
    expiry = int(time.time() + (expiry_hours * 3600))
    
    # Get public key components
    public_numbers = public_key.public_numbers()
    
    # Convert to PEM format
    pem_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Create key entry
    key_entry = {
        "kid": kid,
        "expiry": expiry,
        "private_key": pem_private,
        "public_key_data": {
            "kty": "RSA",
            "kid": kid,
            "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
            "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip("="),
            "alg": "RS256",
            "use": "sig"
        }
    }
    
    return key_entry

def get_valid_key() -> Optional[Dict]:
    """Get a valid (non-expired) key"""
    current_time = int(time.time())
    valid_keys = [k for k in keys if k["expiry"] > current_time]
    return valid_keys[0] if valid_keys else None

def get_expired_key() -> Optional[Dict]:
    """Get an expired key"""
    current_time = int(time.time())
    expired_keys = [k for k in keys if k["expiry"] <= current_time]
    return expired_keys[0] if expired_keys else None

@app.on_event("startup")
async def startup_event():
    """Generate initial keys on startup"""
    # Generate a valid key
    keys.append(generate_key_pair(24))  # 24 hours validity
    # Generate an expired key
    keys.append(generate_key_pair(-1))  # Already expired

@app.get("/.well-known/jwks.json")
async def jwks():
    """Serve the JWKS endpoint"""
    current_time = int(time.time())
    valid_keys = [k["public_key_data"] for k in keys if k["expiry"] > current_time]
    
    return JSONResponse({
        "keys": valid_keys
    })

@app.post("/auth")
async def auth(expired: bool = False):
    """Authentication endpoint that returns a JWT"""
    if expired:
        key = get_expired_key()
        if not key:
            raise HTTPException(status_code=400, message="No expired keys available")
    else:
        key = get_valid_key()
        if not key:
            raise HTTPException(status_code=500, message="No valid keys available")
    
    # Create JWT payload
    payload = {
        "sub": "1234567890",
        "name": "Test User",
        "iat": int(time.time()),
        "exp": key["expiry"]
    }
    
    # Create JWT headers
    headers = {
        "kid": key["kid"]
    }
    
    # Sign the JWT
    token = jwt.encode(
        payload,
        key["private_key"].decode('utf-8'),
        algorithm="RS256",
        headers=headers
    )
    
    return JSONResponse({
        "token": token
    })

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
