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
"""Integration test suite for ``aws_encryption_sdk_cli.key_providers``."""
import os
import shlex

import pytest

import aws_encryption_sdk_cli
from aws_encryption_sdk_cli.internal.identifiers import USER_AGENT_SUFFIX

from .integration_test_utils import encrypt_args_template, is_windows

from .integration_test_utils import kms_redacting_logger_stream  # noqa isort:skip pylint: disable=unused-import

pytestmark = pytest.mark.integ


def test_encrypt_verify_user_agent(tmpdir, kms_redacting_logger_stream):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext)) + " -vvvv"

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))

    all_logs = kms_redacting_logger_stream.getvalue()
    assert USER_AGENT_SUFFIX in all_logs
