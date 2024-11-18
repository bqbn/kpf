from . import get_project_id
from abc import ABC, abstractmethod
from botocore.exceptions import ClientError
from google.cloud import kms_v1
from google.api_core import exceptions
import base64
import boto3
import sys


class UnifiedKMSManager(ABC):
    def __init__(self, provider):
        self.cloud_provider = provider

    @abstractmethod
    def list_keys(self, *args):
        """List CMK keys."""
        pass

    @abstractmethod
    def create_key(self, *args):
        """Create a CMK key."""
        pass

    @abstractmethod
    def encrypt(self, *args):
        pass

    @abstractmethod
    def decrypt(self, *args):
        pass


class GCPKMSManager(UnifiedKMSManager):
    def __init__(self, key_path=None):
        super().__init__("gcp")
        self.client = kms_v1.KeyManagementServiceClient()

        if key_path:
            self.project, self.location, self.key_ring, self.key_id = (
                self.parse_key_path(key_path)
            )
        else:
            self.project = get_project_id()

        self.key_path = key_path

    def parse_key_path(self, key_path: str) -> tuple[str, str, str, str]:
        """
        Parse a Google Cloud KMS resource string into its component parts.

        Args:
            key_path: A string in the format
                "projects/{project}/locations/{location}/keyRings/{keyring}/cryptoKeys/{key}"

        Returns:
            A tuple containing (project_id, location, key_ring, key_id)

        Raises:
            ValueError: If the string doesn't match the expected format
        """
        parts = key_path.split("/")

        # Validate format
        if (
            len(parts) != 8
            or parts[0] != "projects"
            or parts[2] != "locations"
            or parts[4] != "keyRings"
            or parts[6] != "cryptoKeys"
        ):
            raise ValueError(f"Invalid KMS key path format: {key_path}")

        project_id = parts[1]
        location = parts[3]
        key_ring = parts[5]
        key_id = parts[7]

        return (project_id, location, key_ring, key_id)

    def _get_key_path(self):
        return self.client.crypto_key_path(
            self.project, self.location, self.key_ring, self.key_id
        )

    def list_keys(self, project, location, keyring):
        """List all keys in the specified key ring."""
        if not project:
            project = self.project

        key_ring_name = self.client.key_ring_path(project, location, keyring)

        try:
            keys = self.client.list_crypto_keys(request={"parent": key_ring_name})

            print(
                f"Keys in project '{project}', location '{location}', key ring '{keyring}':"
            )
            for key in keys:
                print(f"- {key.name}")

        except exceptions.PermissionDenied as e:
            print(f"Permission Error: {str(e)}", file=sys.stderr)
        except exceptions.NotFound:
            print(
                f"Error: Key ring '{keyring}' not found in project '{project}' and location '{location}'.",
                file=sys.stderr,
            )
        except Exception as e:
            print(f"A {e.__class__.__name__} error occurred: {str(e)}", file=sys.stderr)

    def get_or_create_key(self):
        try:
            return self.client.get_crypto_key(name=self._get_key_path())
        except exceptions.NotFound:
            return self.create_key(
                self.project,
                self.location,
                self.key_ring,
                self.key_id,
                self.key_purpose,
                self.key_algorithm,
            )

    def create_key(self, project, location, keyring, key_id, purpose, algorithm):
        """Create a new key in the specified key ring."""
        if not project:
            project = self.project

        key_ring_path = self.client.key_ring_path(project, location, keyring)

        # Check if the key ring exists, if not, create it
        try:
            response = self.client.get_key_ring(
                request=kms_v1.GetKeyRingRequest(
                    name=key_ring_path,
                )
            )
        except exceptions.NotFound:
            print(f"Key ring '{keyring}' not found. Creating key ring...")
            response = self.client.create_key_ring(
                request=kms_v1.CreateKeyRingRequest(
                    parent=f"projects/{self.project}/locations/{self.location}",
                    key_ring_id=keyring,
                )
            )
            print(f"Key ring '{keyring}' created successfully.")

        purpose_enum = kms_v1.CryptoKey.CryptoKeyPurpose[purpose]
        algorithm_enum = kms_v1.CryptoKeyVersion.CryptoKeyVersionAlgorithm[algorithm]

        crypto_key = kms_v1.CryptoKey(
            purpose=purpose_enum,
            version_template=kms_v1.CryptoKeyVersionTemplate(algorithm=algorithm_enum),
        )

        try:
            response = self.client.create_crypto_key(
                request={
                    "parent": key_ring_path,
                    "crypto_key_id": key_id,
                    "crypto_key": crypto_key,
                }
            )
            print(f"Key created successfully: {response.name}")

        except exceptions.PermissionDenied as e:
            print(f"Permission Error: {str(e)}", file=sys.stderr)
        except exceptions.AlreadyExists:
            print(
                f"Error: A key with ID '{key_id}' already exists in the specified key ring.",
                file=sys.stderr,
            )
        except Exception as e:
            print(f"An error occurred creating key: {str(e)}", file=sys.stderr)

    def encrypt(self, plaintext) -> bytes:
        key_path = self._get_key_path()

        try:
            self.client.get_crypto_key(name=key_path)
        except exceptions.NotFound as e:
            print(f"Key {key_path} does NOT exist! Abort...", file=sys.stderr)
            sys.exit(f"Error: {str(e)}")

        response = self.client.encrypt(
            request={"name": key_path, "plaintext": plaintext}
        )
        return base64.b64encode(response.ciphertext)

    def decrypt(self, ciphertext):
        decoded_ciphertext = base64.b64decode(ciphertext)
        response = self.client.decrypt(
            request={"name": self._get_key_path(), "ciphertext": decoded_ciphertext}
        )
        return response.plaintext.decode()


class AWSKMSManager(UnifiedKMSManager):
    def __init__(self, key_path=None):
        super().__init__("aws")
        self.client = boto3.client("kms")

        if key_path:
            self.key_path = key_path

    def list_keys(self):
        """List all keys in the AWS account."""
        try:
            response = self.client.list_keys()
            region = self.client.meta.region_name
            print(f"Keys in region '{region}':")
            for key in response["Keys"]:
                key_info = self.client.describe_key(KeyId=key["KeyId"])
                print(
                    f"- {key_info['KeyMetadata']['KeyId']} ({key_info['KeyMetadata']['Description']})"
                )
        except ClientError as e:
            print(f"An error occurred: {str(e)}", file=sys.stderr)

    def create_key(self, description, key_usage):
        """Create a new key in AWS KMS."""
        try:
            response = self.client.create_key(
                Description=description,
                KeyUsage=key_usage,
            )
            print(f"Key created successfully: {response['KeyMetadata']['KeyId']}")
        except ClientError as e:
            print(f"An error occurred: {str(e)}", file=sys.stderr)

    def encrypt(self, plaintext) -> bytes:
        response = self.client.encrypt(KeyId=self.key_path, Plaintext=plaintext)
        return base64.b64encode(response["CiphertextBlob"])

    def decrypt(self, ciphertext):
        decoded_ciphertext = base64.b64decode(ciphertext)
        response = self.client.decrypt(
            KeyId=self.key_path, CiphertextBlob=decoded_ciphertext
        )
        return response["Plaintext"].decode()


def get_kms_manager(master_key):
    mk = master_key

    provider = mk.get("provider")
    if provider == "aws":
        return AWSKMSManager(key_path=mk.get("value"))
    elif provider == "gcp":
        return GCPKMSManager(key_path=mk.get("value"))
    else:
        raise ValueError(f"Unsupported provider: `{provider}'.")
