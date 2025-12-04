from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey, VerifyKey
import base64

if __name__ == "__main__":
    for user in ["admin", "alice", "bob", "charlie", "eve"]:
        print(f"Keys for user: {user}")
        # Generate a new public/private key pair
        private_key = PrivateKey.generate()
        public_key = private_key.public_key

        # Generate a new signing key pair
        signing_key = SigningKey.generate()
        verify_key = signing_key.verify_key

        # Print the keys in base64 encoding for easy storage
        with open (f"keys/{user}_priv_key", "wb") as f:
            f.write(base64.b64encode(private_key.encode()))
        with open (f"keys/{user}_priv_key.pub", "wb") as f:
            f.write(base64.b64encode(public_key.encode()))
        with open (f"keys/{user}_sign_key", "wb") as f:
            f.write(base64.b64encode(signing_key.encode()))
        with open (f"keys/{user}_sign_key.pub", "wb") as f:
            f.write(base64.b64encode(verify_key.encode()))
        print("\tEncryption Private Key:", base64.b64encode(private_key.encode()).decode())
        print("\tEncryption Public Key:", base64.b64encode(public_key.encode()).decode())
        print("\tSigning Private Key:", base64.b64encode(signing_key.encode()).decode())
        print("\tSigning Public Key:", base64.b64encode(verify_key.encode()).decode())