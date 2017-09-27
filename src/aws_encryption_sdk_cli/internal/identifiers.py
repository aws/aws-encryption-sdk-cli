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
import logging

import aws_encryption_sdk

__version__ = '1.0.1'

# Using string lookups here rather than direct references to remove special case logic
#  and allow for future cases where known master key providers are provided by optional
#  libraries.
#: Known MasterKeyProviders which can be referenced by provider_id rather than namespace path.
KNOWN_MASTER_KEY_PROVIDERS = {
    'aws-kms': 'aws_encryption_sdk.KMSMasterKeyProvider'
}
#: Suffix added to output files if specific output filename is not specified.
OUTPUT_SUFFIX = {
    'encrypt': '.encrypted',
    'decrypt': '.decrypted'
}

ALGORITHM_NAMES = set([alg for alg in dir(aws_encryption_sdk.Algorithm) if not alg.startswith('_')])
LOGGER_NAME = 'aws_encryption_sdk_cli'
LOGGING_LEVELS = {
    1: logging.WARN,
    2: logging.INFO,
    3: logging.DEBUG
}
MAX_LOGGING_LEVEL = 3
