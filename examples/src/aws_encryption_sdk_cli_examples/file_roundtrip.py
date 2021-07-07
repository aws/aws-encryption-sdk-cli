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
and decrypt a file."""

import shlex
from subprocess import PIPE, Popen

from aws_encryption_sdk_cli_examples.example_test_utils import cmk_arn, is_windows, setup_file


def run(tmpdir):
    expected_plaintext = "Hello World"
    filename = setup_file(tmpdir, expected_plaintext)
    cmk = cmk_arn()

    # Call the encrypt CLI command and ensure that it passes
    encrypt_command = f"bin/encrypt_file.sh {filename} {cmk} {tmpdir}"
    proc = Popen(shlex.split(encrypt_command, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    encrypted_stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise AssertionError("Failed to encrypt", stderr)
    ciphertext_file = filename + ".encrypted"

    # Call the decrypt CLI command and ensure that it passes
    decrypt_command = f"bin/decrypt_file.sh {ciphertext_file} {cmk} {tmpdir}"
    proc = Popen(shlex.split(decrypt_command, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    decrypted_stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise AssertionError("Failed to decrypt", stderr)

    decrypted_file = ciphertext_file + ".decrypted"
    with open(decrypted_file, "r") as f:
        decrypted_text = f.read()
        assert decrypted_text == expected_plaintext
