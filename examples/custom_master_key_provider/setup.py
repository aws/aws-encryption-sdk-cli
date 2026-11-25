"""Sample custom master key provider for the AWS Encryption CLI."""
from setuptools import setup

setup(
    name="aws-encryption-sdk-cli-example-master-key-provider",
    version="0.1.0",
    description="Sample custom master key provider for the AWS Encryption CLI",
    py_modules=["example_master_key_provider"],
    package_dir={"": "src"},
    install_requires=["aws-encryption-sdk-cli>=4.0.0"],
    # Registering the entry point is what makes "provider=example-file-key" resolvable.
    entry_points={
        "aws_encryption_sdk_cli.master_key_providers": [
            "example-file-key = example_master_key_provider:file_key_master_key_provider"
        ]
    },
)
