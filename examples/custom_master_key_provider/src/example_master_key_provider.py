"""Sample custom master key provider for the AWS Encryption CLI.

This provider wraps data keys with AES-256-GCM using a raw wrapping key that is
read from a file. It is meant to show how a custom master key provider is
written and registered, not to be used in production: the wrapping key lives
unprotected on disk.
"""
import os

from aws_encryption_sdk.identifiers import EncryptionKeyType, WrappingAlgorithm
from aws_encryption_sdk.internal.crypto.wrapping_keys import WrappingKey
from aws_encryption_sdk.key_providers.raw import RawMasterKeyProvider
from aws_encryption_sdk_cli.exceptions import BadUserArgumentError

__all__ = ("FileKeyMasterKeyProvider", "file_key_master_key_provider")

PROVIDER_ID = "example-file-key"


class FileKeyMasterKeyProvider(RawMasterKeyProvider):
    """Master key provider that reads each 32-byte AES wrapping key from a file.

    The ``key`` value used on the command line is the path to the key file.
    """

    provider_id = PROVIDER_ID

    def _get_raw_key(self, key_id):
        """Load the wrapping key for ``key_id`` (a file path)."""
        try:
            with open(key_id, "rb") as key_file:
                key_bytes = key_file.read()
        except OSError as error:
            raise BadUserArgumentError("Unable to read wrapping key file {}: {}".format(key_id, error))
        if len(key_bytes) != 32:
            raise BadUserArgumentError("Wrapping key file {} must contain exactly 32 bytes".format(key_id))
        return WrappingKey(
            wrapping_algorithm=WrappingAlgorithm.AES_256_GCM_IV12_TAG16_NO_PADDING,
            wrapping_key=key_bytes,
            wrapping_key_type=EncryptionKeyType.SYMMETRIC,
        )


def file_key_master_key_provider(**kwargs):
    """Entry point called by the AWS Encryption CLI.

    The CLI passes every extra ``name=value`` pair of the ``--wrapping-keys``
    group as a list of strings under ``name``, plus a ``key_ids`` list holding
    all ``key`` values. The CLI adds the keys to the returned provider itself.
    This provider takes no options, so any extra parameter is rejected.
    """
    unexpected = sorted(name for name in kwargs if name != "key_ids")
    if unexpected:
        raise BadUserArgumentError("Unknown parameters for {}: {}".format(PROVIDER_ID, ", ".join(unexpected)))
    return FileKeyMasterKeyProvider()
