#!/usr/bin/env python3
import base64, json, os, requests
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

KEY_FILE = os.path.join(os.path.dirname(__file__), 'rsa_keys.json')

def gen_keypair():
    key = rsa.generate_private_key(65537, 2048, default_backend())
    return {
        'private': key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ).decode(),
        'public': key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    }

def save_keys(data, path=KEY_FILE):
    tmp = path + '.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f)
    os.replace(tmp, path)

def load_keys(path=KEY_FILE):
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    d = gen_keypair()
    save_keys(d, path)
    return d

def get_private_key(pem=None):
    if pem is None:
        pem = load_keys()['private']
    return serialization.load_pem_private_key(pem.encode(), None, default_backend())

def get_public_key(pem=None):
    if pem is None:
        pem = load_keys()['public']
    return serialization.load_pem_public_key(pem.encode(), default_backend())

KEY_SIZE = 2048
ENCRYPT_MAX = KEY_SIZE // 8 - 11  # 245 for 2048-bit
DECRYPT_CHUNK = KEY_SIZE // 8      # 256 for 2048-bit

def rsa_encrypt(plaintext, pub_key=None):
    pk = get_public_key(pub_key)
    raw = plaintext.encode() if isinstance(plaintext, str) else plaintext
    chunks = [raw[i:i+ENCRYPT_MAX] for i in range(0, len(raw), ENCRYPT_MAX)]
    result = b''
    for c in chunks:
        result += pk.encrypt(c, padding.PKCS1v15())
    return base64.b64encode(result).decode()

def rsa_decrypt(cipherb64, priv_key=None):
    pk = get_private_key(priv_key)
    raw = base64.b64decode(cipherb64)
    chunks = [raw[i:i+DECRYPT_CHUNK] for i in range(0, len(raw), DECRYPT_CHUNK)]
    result = b''
    for c in chunks:
        result += pk.decrypt(c, padding.PKCS1v15())
    return result.decode()

class RSAAgentClient:
    def __init__(self, agent_url=None):
        self.agent_url = agent_url

    def encrypt(self, plaintext):
        if self.agent_url:
            r = requests.post(self.agent_url, params={'encrypt': '1'}, data=plaintext, timeout=10)
            return r.text.strip()
        return rsa_encrypt(plaintext)

    def decrypt(self, ciphertext):
        if self.agent_url:
            r = requests.post(self.agent_url, data=ciphertext, timeout=10)
            return r.text.strip()
        return rsa_decrypt(ciphertext)

    def encrypt_payload(self, cmd):
        return self.encrypt(cmd)

    def decrypt_response(self, resp_text):
        return self.decrypt(resp_text)

if __name__ == '__main__':
    keys = load_keys()
    print('[+] RSA Keys ready')
    print('  Private: %d bytes' % len(keys['private']))
    print('  Public:  %d bytes' % len(keys['public']))
    test = 'cat /flag;whoami'
    enc = rsa_encrypt(test)
    dec = rsa_decrypt(enc)
    print('[+] Encrypt test: %s... (%d bytes)' % (enc[:40], len(enc)))
    print('[+] Decrypt test: %s' % dec)
    assert dec == test, 'RSA encrypt/decrypt failed!'
    print('[+] RSA OK')
