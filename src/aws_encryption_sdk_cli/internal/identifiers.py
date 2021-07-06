# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Static identifier values for the AWS Encryption SDK CLI."""
from enum import Enum

import aws_encryption_sdk

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Set  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass


__all__ = (
    "OUTPUT_SUFFIX",
    "ALGORITHM_NAMES",
    "MASTER_KEY_PROVIDERS_ENTRY_POINT",
    "PLUGIN_NAMESPACE_DIVIDER",
    "USER_AGENT_SUFFIX",
    "DEFAULT_MASTER_KEY_PROVIDER",
    "OperationResult",
)
__version__ = "3.1.0"  # type: str

#: Suffix added to output files if specific output filename is not specified.
OUTPUT_SUFFIX = {
    "encrypt": ".encrypted",
    "decrypt": ".decrypted",
    "decrypt-unsigned": ".decrypted",
}  # type: Dict[str, str]

ALGORITHM_NAMES = {
    alg for alg in dir(aws_encryption_sdk.Algorithm) if not alg.startswith("_")
}  # type: Set[aws_encryption_sdk.Algorithm]
MASTER_KEY_PROVIDERS_ENTRY_POINT = "aws_encryption_sdk_cli.master_key_providers"
PLUGIN_NAMESPACE_DIVIDER = "::"
USER_AGENT_SUFFIX = "AwsEncryptionSdkCli/{}".format(__version__)
DEFAULT_MASTER_KEY_PROVIDER = "aws-encryption-sdk-cli" + PLUGIN_NAMESPACE_DIVIDER + "aws-kms"


class OperationResult(Enum):
    """Identifies the resulting state of an operation.

    :param bool needs_cleanup: If true, the output file needs to be deleted
    """

    FAILED = (True,)
    SUCCESS = (False,)
    SKIPPED = (False,)
    FAILED_VALIDATION = (True,)

    def __init__(self, needs_cleanup):
        # type: (bool) -> None
        """Prepares new OperationResult."""
        self.needs_cleanup = needs_cleanup
