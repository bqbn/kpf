from google.cloud import secretmanager
from google.api_core.exceptions import NotFound


def list_versions(secret, project_id):
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret}"
    response = client.list_secret_versions(request={"parent": name})
    for version in response:
        state_name = secretmanager.SecretVersion.State(version.state).name
        print(f"Version: {version.name}, State: {state_name}")


def disable_version(secret, version_number, project_id):
    client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{project_id}/secrets/{secret}/versions/{version_number}"
    client.disable_secret_version(name=name)
    print(f"Disabled version {version_number} of {secret}.")


def create_or_update_secret_data(secret_name, project_id, data: bytes):
    client = secretmanager.SecretManagerServiceClient()

    parent = f"projects/{project_id}"
    secret_path = f"{parent}/secrets/{secret_name}"

    # Check if the secret exists
    try:
        client.get_secret(name=secret_path)
    except NotFound:
        print(f"Creating new secret '{secret_name}'...")
        secret = client.create_secret(
            request={
                "parent": parent,
                "secret_id": secret_name,
                "secret": {"replication": {"automatic": {}}},
            }
        )
        print(f"Created secret '{secret_name}'.")

    # Upload the datfile as a new version of the secret
    client.add_secret_version(
        request={
            "parent": secret_path,
            "payload": {"data": data},
        }
    )
    print(f"Secret uploaded as a new version for {secret_name}.")
