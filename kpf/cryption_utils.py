import sys


class KMSCryptor:
    def __init__(self, kms_manager, encrypted_dek):
        self.kms_manager = kms_manager
        self.encrypted_dek = encrypted_dek

    def encrypt(self, plain_dek) -> bytes:
        encrypted_dek = self.kms_manager.encrypt(plain_dek)

        return encrypted_dek

    def decrypt(self) -> bytes:
        try:
            dek = self.kms_manager.decrypt(self.encrypted_dek.encode())
        except Exception:
            print(
                f"Failed to decrypt the DEK `{self.encrypted_dek}'.",
                file=sys.stderr,
            )
            raise

        return dek
