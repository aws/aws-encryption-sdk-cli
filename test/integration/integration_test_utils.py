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
from distutils.spawn import find_executable  # distutils confuses pylint: disable=import-error,no-name-in-module
import logging
import os
import platform

import pytest
import six

from aws_encryption_sdk_cli.internal import logging_utils

SKIP_MESSAGE = (
    'Required environment variables not found. Skipping integration tests.'
    ' See integration tests README.rst for more information.'
)
WINDOWS_SKIP_MESSAGE = 'Skipping test on Windows'
TEST_CONTROL = 'AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_CONTROL'
AWS_KMS_KEY_ID = 'AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID'


def is_windows():
    return any(platform.win32_ver())


def skip_tests():
    """Only run tests if both required environment variables are found."""
    test_control = os.environ.get(TEST_CONTROL, None)
    key_id = os.environ.get(AWS_KMS_KEY_ID, None)
    return not (test_control == 'RUN' and key_id is not None)


def aws_encryption_cli_is_findable():
    path = find_executable('aws-encryption-cli')
    if path is None:
        UserWarning('aws-encryption-cli executable could not be found')
        return False
    return True


@pytest.fixture
def cmk_arn():
    """Retrieves the target CMK ARN from environment variable."""
    return os.environ.get(AWS_KMS_KEY_ID)


def encrypt_args_template(metadata=False, caching=False):
    template = '-e -i {source} -o {target} --encryption-context a=b c=d -m key=' + cmk_arn()
    if metadata:
        template += ' {metadata}'
    else:
        template += ' -S'
    if caching:
        template += ' --caching capacity=10 max_age=60.0'
    return template


def decrypt_args_template(metadata=False):
    template = '-d -i {source} -o {target}'
    if metadata:
        template += ' {metadata}'
    else:
        template += ' -S'
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
