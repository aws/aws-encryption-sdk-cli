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

import boto3
import pytest

from aws_encryption_sdk_cli.internal import logging_utils

from ..integration_test_utils import cmk_arn, kms_redacting_logger_stream  # noqa pylint: disable=unused-import

pytestmark = pytest.mark.integ


@pytest.fixture
def kms_client(cmk_arn):
    region = cmk_arn.split(":")[3]
    return boto3.client("kms", region_name=region)


def test_kms_generate_data_key(kms_redacting_logger_stream, kms_client, cmk_arn):
    response = kms_client.generate_data_key(KeyId=cmk_arn, NumberOfBytes=32)

    log_output = kms_redacting_logger_stream.getvalue()

    assert log_output.count(logging_utils._REDACTED) == 1
    assert log_output.count(cmk_arn) == 2
    assert codecs.decode(base64.b64encode(response["Plaintext"]), "utf-8") not in log_output
    assert log_output.count(codecs.decode(base64.b64encode(response["CiphertextBlob"]), "utf-8")) == 1


def test_kms_encrypt(kms_redacting_logger_stream, kms_client, cmk_arn):
    raw_plaintext = b"some secret data"
    response = kms_client.encrypt(KeyId=cmk_arn, Plaintext=raw_plaintext)

    log_output = kms_redacting_logger_stream.getvalue()

    assert log_output.count(logging_utils._REDACTED) == 1
    assert log_output.count(cmk_arn) == 2
    assert codecs.decode(base64.b64encode(raw_plaintext), "utf-8") not in log_output
    assert log_output.count(codecs.decode(base64.b64encode(response["CiphertextBlob"]), "utf-8")) == 1


def test_kms_decrypt(kms_redacting_logger_stream, kms_client, cmk_arn):
    raw_plaintext = b"some secret data"
    encrypt_response = kms_client.encrypt(KeyId=cmk_arn, Plaintext=raw_plaintext)
    kms_client.decrypt(CiphertextBlob=encrypt_response["CiphertextBlob"])

    log_output = kms_redacting_logger_stream.getvalue()

    assert log_output.count(logging_utils._REDACTED) == 2
    assert log_output.count(cmk_arn) == 3
    assert codecs.decode(base64.b64encode(raw_plaintext), "utf-8") not in log_output
    assert log_output.count(codecs.decode(base64.b64encode(encrypt_response["CiphertextBlob"]), "utf-8")) == 2
