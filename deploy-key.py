import boto3
from botocore.exceptions import ClientError
import os

def get_secret():
    # Name of the secret and AWS region
    secret_name = "sagemaker/deploy-key"  # Update with your secret's name
    region_name = "us-east-1"  # Update with your region

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        # Fetch the secret
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
    except ClientError as e:
        # Handle possible exceptions
        print(f"Failed to retrieve secret: {e}")
        raise e

    # Extract the secret value
    return get_secret_value_response['SecretString']


def configure_ssh(ssh_key):
    # Define the SSH key file path
    ssh_key_path = "/root/.ssh/sagemaker_deploy_key"
    ssh_config_path = "/root/.ssh/config"

    # Create the .ssh directory if it doesn't exist
    os.makedirs(os.path.dirname(ssh_key_path), exist_ok=True)

    # Save the SSH key to a file
    with open(ssh_key_path, "w") as f:
        f.write(ssh_key)

    # Set secure permissions for the SSH key
    os.chmod(ssh_key_path, 0o600)

    # Create an SSH configuration file
    ssh_config = f"""
Host github.com
    HostName github.com
    User git
    IdentityFile {ssh_key_path}
    StrictHostKeyChecking no
"""
    with open(ssh_config_path, "w") as f:
        f.write(ssh_config)

    # Set secure permissions for the SSH configuration file
    os.chmod(ssh_config_path, 0o600)

    print("SSH key and configuration have been successfully set up.")


def main():
    # Retrieve the SSH key from Secrets Manager
    ssh_key = get_secret()

    # Configure SSH with the retrieved key
    configure_ssh(ssh_key)

    # Test the SSH connection to GitHub (optional)
    test_ssh_command = "ssh -T git@github.com"
    response = os.system(test_ssh_command)
    if response == 0:
        print("SSH connection to GitHub is successful.")
    else:
        print("Failed to connect to GitHub. Check the SSH configuration.")


if __name__ == "__main__":
    main()
