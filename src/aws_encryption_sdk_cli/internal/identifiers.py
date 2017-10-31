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
from typing import Dict, Set  # noqa pylint: disable=unused-import

import aws_encryption_sdk

__version__ = '1.0.2'  # type: str

#: Suffix added to output files if specific output filename is not specified.
OUTPUT_SUFFIX = {
    'encrypt': '.encrypted',
    'decrypt': '.decrypted'
}  # type: Dict[str, str]

ALGORITHM_NAMES = set([
    alg for alg in dir(aws_encryption_sdk.Algorithm) if not alg.startswith('_')
])  # type: Set[aws_encryption_sdk.Algorithm]
MASTER_KEY_PROVIDERS_ENTRY_POINT = 'aws_encryption_sdk_cli.master_key_providers'
PLUGIN_NAMESPACE_DIVIDER = '::'
