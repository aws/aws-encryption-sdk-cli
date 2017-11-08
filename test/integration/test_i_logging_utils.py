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
"""Unit testing suite for ``aws_encryption_sdk_cli.internal.logging``."""
import base64
import codecs
import logging
import os

import boto3
import pytest
import six

from aws_encryption_sdk_cli.internal import logging_utils
from .test_i_aws_encryption_sdk_cli import _should_run_tests as meta_should_run_tests

AWS_KMS_KEY_ID = 'AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID'


def _should_run_tests():
    return AWS_KMS_KEY_ID in os.environ and meta_should_run_tests()


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


@pytest.fixture
def kms_key():
    return os.environ.get(AWS_KMS_KEY_ID)


@pytest.fixture
def kms_client(kms_key):
    region = kms_key.split(':')[3]
    return boto3.client('kms', region_name=region)


@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_kms_generate_data_key(kms_redacting_logger_stream, kms_client, kms_key):
    response = kms_client.generate_data_key(KeyId=kms_key, NumberOfBytes=32)

    log_output = kms_redacting_logger_stream.getvalue()

    assert log_output.count(logging_utils._REDACTED) == 1
    assert log_output.count(kms_key) == 2
    assert codecs.decode(base64.b64encode(response['Plaintext']), 'utf-8') not in log_output
    assert log_output.count(codecs.decode(base64.b64encode(response['CiphertextBlob']), 'utf-8')) == 1


@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_kms_encrypt(kms_redacting_logger_stream, kms_client, kms_key):
    raw_plaintext = b'some secret data'
    response = kms_client.encrypt(KeyId=kms_key, Plaintext=raw_plaintext)

    log_output = kms_redacting_logger_stream.getvalue()

    assert log_output.count(logging_utils._REDACTED) == 1
    assert log_output.count(kms_key) == 2
    assert codecs.decode(base64.b64encode(raw_plaintext), 'utf-8') not in log_output
    assert log_output.count(codecs.decode(base64.b64encode(response['CiphertextBlob']), 'utf-8')) == 1


@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_kms_decrypt(kms_redacting_logger_stream, kms_client, kms_key):
    raw_plaintext = b'some secret data'
    encrypt_response = kms_client.encrypt(KeyId=kms_key, Plaintext=raw_plaintext)
    kms_client.decrypt(CiphertextBlob=encrypt_response['CiphertextBlob'])

    log_output = kms_redacting_logger_stream.getvalue()

    assert log_output.count(logging_utils._REDACTED) == 2
    assert log_output.count(kms_key) == 3
    assert codecs.decode(base64.b64encode(raw_plaintext), 'utf-8') not in log_output
    assert log_output.count(codecs.decode(base64.b64encode(encrypt_response['CiphertextBlob']), 'utf-8')) == 2
