# Copyright 2021 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
"""Example showing basic usage of the AWS Encryption CLI to encrypt
input from stdin and output it to stdout."""

import shlex
from subprocess import PIPE, Popen

from aws_encryption_sdk_cli_examples.example_test_utils import cmk_arn, is_windows, setup_file

def run():
    expected_plaintext = "Hello World"
    cmk = cmk_arn()

    # Call the encrypt CLI command and ensure that it passes
    encrypt_command = "encrypt_command_line.sh '{}' {}".format(expected_plaintext, cmk)
    proc = Popen(shlex.split(encrypt_command, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    encrypted_stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise AssertionError("Failed to encrypt", stderr)
    ciphertext_string = encrypted_stdout.decode("utf-8")

    # Call the decrypt CLI command and ensure that it passes
    decrypt_command = "decrypt_command_line.sh {} {}".format(ciphertext_string, cmk)
    proc = Popen(shlex.split(decrypt_command, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    decrypted_stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise AssertionError("Failed to decrypt", stderr)

    decrypted_plaintext = decrypted_stdout.strip().decode("utf-8")
    assert decrypted_plaintext == expected_plaintext
