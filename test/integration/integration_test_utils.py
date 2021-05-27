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
"""Utility functions to handle configuration, credentials setup, and test skip decision making for integration tests."""
import logging
import os
import platform
from distutils.spawn import find_executable  # distutils confuses pylint: disable=import-error,no-name-in-module

import pytest
import six

from aws_encryption_sdk_cli.internal import logging_utils

WINDOWS_SKIP_MESSAGE = "Skipping test on Windows"
AWS_KMS_KEY_ID = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID"


def is_windows():
    return any(platform.win32_ver())


def aws_encryption_cli_is_findable():
    path = find_executable("aws-encryption-cli")
    if path is None:
        UserWarning("aws-encryption-cli executable could not be found")
        return False
    return True


def cmk_arn_value():
    """Retrieves the target CMK ARN from environment variable."""
    arn = os.environ.get(AWS_KMS_KEY_ID, None)
    if arn is None:
        raise ValueError(
            'Environment variable "{}" must be set to a valid KMS CMK ARN for integration tests to run'.format(
                AWS_KMS_KEY_ID
            )
        )
    if arn.startswith("arn:") and ":alias/" not in arn:
        return arn
    raise ValueError("KMS CMK ARN provided for integration tests must be a key not an alias")


@pytest.fixture
def cmk_arn():
    """As of Pytest 4.0.0, fixtures cannot be called directly."""
    return cmk_arn_value()


def encrypt_args_template(metadata=False, caching=False, encode=False, decode=False):
    template = "-e -i {source} -o {target} --encryption-context a=b c=d -w key=" + cmk_arn_value()
    if metadata:
        template += " {metadata}"
    else:
        template += " -S"
    if caching:
        template += " --caching capacity=10 max_age=60.0"
    if encode:
        template += " --encode"
    if decode:
        template += " --decode"
    return template


def decrypt_args_template(metadata=False, encode=False, decode=False, discovery=True, buffer=False):
    template = "-d -i {source} -o {target} "
    if metadata:
        template += " {metadata}"
    else:
        template += " -S"
    if encode:
        template += " --encode"
    if decode:
        template += " --decode"
    if discovery:
        template += " --wrapping-keys discovery=true"
    if buffer:
        template += " --buffer"
    return template


def decrypt_unsigned_args_template(metadata=False):
    template = "--decrypt-unsigned -i {source} -o {target} --wrapping-keys discovery=true"
    if metadata:
        template += " {metadata}"
    else:
        template += " -S"
    return template


@pytest.fixture
def kms_redacting_logger_stream():
    output_stream = six.StringIO()
    formatter = logging_utils._KMSKeyRedactingFormatter(logging_utils.FORMAT_STRING)
    handler = logging.StreamHandler(stream=output_stream)
    handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return output_stream
