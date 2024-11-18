from . import get_project_id
from .cryption_utils import KMSCryptor
from .kms_utils import get_kms_manager
from .secret_utils import create_or_update_secret_data, list_versions, disable_version
from cryptography.fernet import Fernet
from difflib import unified_diff
from google.api_core.exceptions import NotFound
from google.cloud import secretmanager
from pathlib import Path
import json
import os
import subprocess
import sys
import tempfile
import yaml


class DekMissingError(Exception):
    pass


class InconsistentDecryptedData(Exception):
    pass


class UnknownFileExtension(Exception):
    pass


class EncryptedFile:
    def __str__(self) -> str:
        return str(self.file_path)

    def __init__(self, file_path):
        self.file_path = Path(file_path)

        suffix = self.file_path.suffix
        if suffix == ".json":
            self.loader = json.load
            self.string_loader = json.loads
            self.load_error = json.JSONDecodeError
            self.dumper = json.dumps
        elif suffix in (".yaml", ".yml"):
            self.loader = yaml.safe_load
            self.string_loader = yaml.safe_load
            self.load_error = yaml.YAMLError
            self.dumper = lambda data, **kwargs: yaml.dump(
                data, **kwargs, default_flow_style=False
            )
        elif suffix in (".txt"):
            # All text files that are neither json nor yaml format can be encrypted
            # and then saved in json format.
            self.loader = json.load
            self.string_loader = json.loads
            self.load_error = json.JSONDecodeError
            self.dumper = json.dumps
        else:
            # We cannot handle non-text files yet.
            raise UnknownFileExtension(
                f"Unrecognized file extension. Try .json, .yaml, or .yml."
            )

        self.is_not_new = True if self.file_path.exists() else False

        self.contents = {}
        self.encryptors = []
        self.decryptors = []

    def _get_dek(self):
        """Return a data encryption key."""
        return Fernet.generate_key()

    def load_contents(self):
        with open(self.file_path, "rb") as file:
            file_content = self.loader(file)
            return file_content

    def load_decryptors(self):
        decryptors = []
        for d in self.contents.get("decryptors", []):
            kms_manager = get_kms_manager(d)
            encrypted_dek = d.get("dek")
            decryptors.append(KMSCryptor(kms_manager, encrypted_dek))

        return decryptors

    def add_encryptors(self, master_keys):
        for mk in master_keys:
            self.encryptors.append(get_kms_manager(mk))

    def decrypt(self) -> bytes:
        self.contents = self.load_contents()
        self.decryptors = self.load_decryptors()

        encrypted_data = self.contents.get("data")
        if not encrypted_data:
            raise ValueError(
                f'{self} does NOT have a "data" filed or the field is empty.'
            )

        decrypted_dek = b""

        for d in self.decryptors:
            try:
                decrypted = d.decrypt()
            except Exception as e:
                print(
                    f"Warning: an error happened while decrypting the DEK using one of the configured cryptors.",
                    f"The error was `{e}'.",
                    file=sys.stderr,
                )
                continue

            if decrypted_dek == b"":
                decrypted_dek = decrypted
            else:
                if decrypted_dek == decrypted:
                    continue
                else:
                    raise InconsistentDecryptedData(
                        f"Inconsistent decrypted data by {d}."
                    )

        if not decrypted_dek:
            raise ValueError(f"Failed to decrypt the DEK using any of the decryptors.")

        # Decrypt the data
        try:
            fernet = Fernet(decrypted_dek)
            decrypted_data = fernet.decrypt(encrypted_data)
        except Exception:
            raise

        return decrypted_data

    # define an alias
    get_decrypted_data = decrypt

    def encrypt(self, plain_data):
        content = {"data": "", "decryptors": []}

        dek = self._get_dek()
        fernet = Fernet(dek)
        content["data"] = fernet.encrypt(plain_data).decode()

        for e in self.encryptors:
            try:
                decryptor = {
                    "provider": e.cloud_provider,
                    "value": e.key_path,
                    "dek": e.encrypt(dek).decode(),
                }
            except Exception as e:
                print(f"Error encrypting file: {str(e)}", file=sys.stderr)
                raise e

            content["decryptors"].append(decryptor)

        return self.dumper(content, indent=2).encode()

    def encrypt_file(self, file_path) -> bytes:
        file = Path(file_path)

        if not file.is_file() or not file.exists():
            raise ValueError(f"{file_path} is not a file or does not exist.")

        with open(file, "rb") as f:
            plain_data = f.read()

        return self.encrypt(plain_data)

    def is_valid(self) -> bool:
        try:
            decrypted = self.decrypt()
        except Exception as e:
            print(f"Failed to decrypt {self.file_path}!", file=sys.stderr)
            print(e, file=sys.stderr)
            return False

        try:
            data = self.string_loader(decrypted)
            print(self.dumper(data, indent=2))
            print("OK!")
            return True
        except self.load_error as e:
            print(f"Failed to parse {self.file_path}!", file=sys.stderr)
            print(e, file=sys.stderr)
            return False
        except IOError as e:
            print(f"Error reading file {self.file_path}: {e}", file=sys.stderr)
            return False

    def edit(self):
        """Decrypt the file, open it in an editor, and re-encrypt it after editing."""

        # Check if the file exists and handle editing accordingly.
        if self.is_not_new:
            decrypted_data = self.decrypt()
        else:
            print(f"Creating a new encrypted file: {self.file_path}...")
            decrypted_data = b""

        edited_content = self._edit_file(decrypted_data)

        # Encrypt the content after editing
        encrypted_edited_content = self.encrypt(edited_content)

        # Write the edited content to the file
        with open(self.file_path, "wb") as file:
            file.write(encrypted_edited_content)

        action = "successfully encrypted and saved" if self.is_not_new else "created"
        print(f"File {self.file_path} {action}.")

    def _edit_file(self, decrypted_data):
        """Create a temporary file, open it in an editor, and return the edited content."""
        with tempfile.NamedTemporaryFile(
            suffix=".tmp", delete=True, delete_on_close=False
        ) as temp_file:
            temp_file.write(decrypted_data)
            temp_file.flush()

            editor = os.environ.get("EDITOR", "vim")
            try:
                subprocess.run([editor, temp_file.name], check=True)
            except subprocess.CalledProcessError as e:
                print(f"{editor} failed with code {e.returncode}")
                raise e

            # Read the edited content
            with open(temp_file.name, "rb") as edited_file:
                return edited_file.read()

    def _get_secret_name(self):
        return self.file_path.stem

    def update_secret(self):
        project_id = get_project_id()
        secret_name = self._get_secret_name()

        client = secretmanager.SecretManagerServiceClient()

        # Access the latest version of the secret
        name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
        try:
            response = client.access_secret_version(name=name)
            remote_version = response.payload.data.decode()
        except NotFound:
            print(f"Warning: Secret version '{name}' not found.")
            remote_version = ""

        # Perform the diff operation
        diff = list(
            unified_diff(
                remote_version.splitlines(keepends=True),
                self.get_decrypted_data().decode().splitlines(keepends=True),
            )
        )
        if not diff:
            print(
                f"No difference is found. The content of {self} matches the latest version of {secret_name}."
            )
            return

        print("".join(diff))
        answer = input("Would you like to continue (yes/no)?: ")

        if answer.lower() == "yes":
            # Validate the datfile
            if self.is_valid():
                create_or_update_secret_data(
                    secret_name, project_id, self.get_decrypted_data()
                )

                # List all versions of the secret
                list_versions(secret_name, project_id)

                vernum = input(
                    "Would you like to disable a version? Please enter a version number or just enter to skip: "
                )

                if vernum.isdigit():
                    disable_version(secret_name, vernum, project_id)
                    list_versions(secret_name, project_id)
