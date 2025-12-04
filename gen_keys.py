from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey
import base64

if __name__ == "__main__":
    for user in ["admin", "alice", "bob", "charlie", "eve", "pb", "n1", "n2"]:
        print(f"Keys for user: {user}")
        private_key = PrivateKey.generate()
        signing_key = SigningKey.generate()

        with open (f"keys/{user}_priv_key", "wb") as f:
            f.write(base64.b64encode(private_key.encode()))
        with open (f"keys/{user}_sign_key", "wb") as f:
            f.write(base64.b64encode(signing_key.encode()))