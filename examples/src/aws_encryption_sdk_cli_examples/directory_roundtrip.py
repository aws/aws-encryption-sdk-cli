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
and decrypt all files in a directory."""

import os
import shlex
from subprocess import PIPE, Popen

from aws_encryption_sdk_cli_examples.example_test_utils import cmk_arn, is_windows, setup_files


def run(tmpdir):
    cmk = cmk_arn()

    # Create directories that will store plaintext, ciphertexts,
    plaintext_directory = os.path.join(str(tmpdir), "plaintext")
    encrypt_directory = os.path.join(str(tmpdir), "encrypted")
    decrypt_directory = os.path.join(str(tmpdir), "decrypted")
    os.mkdir(plaintext_directory)
    os.mkdir(encrypt_directory)
    os.mkdir(decrypt_directory)

    original_files = setup_files(plaintext_directory, 10)

    # Call the encrypt CLI command and ensure that it passes
    encrypt_command = "encrypt_directory.sh {} {} {}".format(plaintext_directory, cmk, encrypt_directory)
    proc = Popen(shlex.split(encrypt_command, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    encrypted_stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise AssertionError("Failed to encrypt", stderr)

    # Call the decrypt CLI command and ensure that it passes
    decrypt_command = "decrypt_directory.sh {} {} {}".format(encrypt_directory, cmk, decrypt_directory)
    proc = Popen(shlex.split(decrypt_command, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    decrypted_stdout, stderr = proc.communicate()
    if proc.returncode != 0:
        raise AssertionError("Failed to decrypt", stderr)

    # For each original file, find the decrypted version of it, decrypt it, and compare the contents
    for original_file in original_files:
        with open(original_file, "r") as f1:
            original_plaintext = f1.read()
            decrypted_file = os.path.join(decrypt_directory, os.path.basename(original_file) + ".encrypted.decrypted")
            with open (decrypted_file) as f2:
                decrypted_plaintext = f2.read()
                assert decrypted_plaintext == original_plaintext
