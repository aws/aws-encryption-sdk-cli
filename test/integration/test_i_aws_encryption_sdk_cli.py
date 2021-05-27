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
"""Integration testing suite for AWS Encryption SDK CLI."""
# pylint: disable=too-many-lines
import base64
import filecmp
import json
import os
import shlex
import shutil
from subprocess import PIPE, Popen

import pytest

import aws_encryption_sdk_cli

from .integration_test_utils import (
    WINDOWS_SKIP_MESSAGE,
    aws_encryption_cli_is_findable,
    cmk_arn_value,
    decrypt_args_template,
    decrypt_unsigned_args_template,
    encrypt_args_template,
    is_windows,
)

pytestmark = pytest.mark.integ


def test_encrypt_with_metadata_output_write_to_file(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    metadata = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template(metadata=True).format(
        source=str(plaintext), target=str(ciphertext), metadata="--metadata-output " + str(metadata)
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))

    raw_metadata = metadata.read()
    output_metadata = json.loads(raw_metadata)
    for key, value in (("a", "b"), ("c", "d")):
        assert output_metadata["header"]["encryption_context"][key] == value
    assert output_metadata["mode"] == "encrypt"
    assert output_metadata["input"] == str(plaintext)
    assert output_metadata["output"] == str(ciphertext)


def test_encrypt_with_metadata_full_file_path(tmpdir):
    plaintext_filename = "source_plaintext"
    plaintext_file = tmpdir.join(plaintext_filename)
    plaintext_file.write_binary(os.urandom(1024))
    plaintext_file_full_path = str(plaintext_file)
    ciphertext_filename = "ciphertext"
    ciphertext_file = tmpdir.join(ciphertext_filename)
    ciphertext_file_full_path = str(ciphertext_file)
    metadata = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template(metadata=True).format(
        source=plaintext_filename, target=ciphertext_filename, metadata="--metadata-output " + str(metadata)
    )

    with tmpdir.as_cwd():
        aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))

    raw_metadata = metadata.read()
    output_metadata = json.loads(raw_metadata)
    assert output_metadata["input"] == plaintext_file_full_path
    assert output_metadata["output"] == ciphertext_file_full_path


def test_encrypt_with_metadata_output_write_to_stdout(tmpdir, capsys):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")

    encrypt_args = encrypt_args_template(metadata=True).format(
        source=str(plaintext), target=str(ciphertext), metadata="--metadata-output -"
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))

    out, _err = capsys.readouterr()
    output_metadata = json.loads(out)
    for key, value in (("a", "b"), ("c", "d")):
        assert output_metadata["header"]["encryption_context"][key] == value
    assert output_metadata["mode"] == "encrypt"
    assert output_metadata["input"] == str(plaintext)
    assert output_metadata["output"] == str(ciphertext)


def test_cycle_with_metadata_output_append(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    metadata = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template(metadata=True).format(
        source=str(plaintext), target=str(ciphertext), metadata="--metadata-output " + str(metadata)
    )
    decrypt_args = decrypt_args_template(metadata=True).format(
        source=str(ciphertext), target=str(decrypted), metadata="--metadata-output " + str(metadata)
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    output_metadata = [json.loads(line) for line in metadata.readlines()]
    for line in output_metadata:
        for key, value in (("a", "b"), ("c", "d")):
            assert line["header"]["encryption_context"][key] == value

    assert output_metadata[0]["mode"] == "encrypt"
    assert output_metadata[0]["input"] == str(plaintext)
    assert output_metadata[0]["output"] == str(ciphertext)
    assert "header_auth" not in output_metadata[0]
    assert output_metadata[1]["mode"] == "decrypt"
    assert output_metadata[1]["input"] == str(ciphertext)
    assert output_metadata[1]["output"] == str(decrypted)
    assert "header_auth" in output_metadata[1]


def test_cycle_explicit_discovery_true_no_filter(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    metadata = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template(metadata=True).format(
        source=str(plaintext), target=str(ciphertext), metadata="--metadata-output " + str(metadata)
    )
    decrypt_args = decrypt_args_template(metadata=True, discovery=True).format(
        source=str(ciphertext), target=str(decrypted), metadata="--metadata-output " + str(metadata)
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    output_metadata = [json.loads(line) for line in metadata.readlines()]
    for line in output_metadata:
        for key, value in (("a", "b"), ("c", "d")):
            assert line["header"]["encryption_context"][key] == value

    assert output_metadata[0]["mode"] == "encrypt"
    assert output_metadata[0]["input"] == str(plaintext)
    assert output_metadata[0]["output"] == str(ciphertext)
    assert "header_auth" not in output_metadata[0]
    assert output_metadata[1]["mode"] == "decrypt"
    assert output_metadata[1]["input"] == str(ciphertext)
    assert output_metadata[1]["output"] == str(decrypted)
    assert "header_auth" in output_metadata[1]


def test_cycle_discovery_true_filter_wrong_account(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    metadata = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template(metadata=True).format(
        source=str(plaintext), target=str(ciphertext), metadata="--metadata-output " + str(metadata)
    )
    decrypt_args = decrypt_args_template(metadata=True, discovery=False).format(
        source=str(ciphertext), target=str(decrypted), metadata="--metadata-output " + str(metadata)
    )
    decrypt_args += " -w discovery=true discovery-account=1234 discovery-partition=aws"

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    message = aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    output_metadata = [json.loads(line) for line in metadata.readlines()]
    for line in output_metadata:
        for key, value in (("a", "b"), ("c", "d")):
            assert line["header"]["encryption_context"][key] == value

    assert output_metadata[0]["mode"] == "encrypt"
    assert output_metadata[0]["input"] == str(plaintext)
    assert output_metadata[0]["output"] == str(ciphertext)
    assert "header_auth" not in output_metadata[0]
    assert not decrypted.isfile()
    assert "not allowed by this Master Key Provider" in message


def test_cycle_discovery_true_filter_wrong_partition(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    metadata = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template(metadata=True).format(
        source=str(plaintext), target=str(ciphertext), metadata="--metadata-output " + str(metadata)
    )
    decrypt_args = decrypt_args_template(metadata=True, discovery=False).format(
        source=str(ciphertext), target=str(decrypted), metadata="--metadata-output " + str(metadata)
    )
    arn = cmk_arn_value()
    account = arn.split(":")[4]
    decrypt_args += " -w discovery=true discovery-account={account} discovery-partition=aws-gov".format(account=account)

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    message = aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    output_metadata = [json.loads(line) for line in metadata.readlines()]
    for line in output_metadata:
        for key, value in (("a", "b"), ("c", "d")):
            assert line["header"]["encryption_context"][key] == value

    assert output_metadata[0]["mode"] == "encrypt"
    assert output_metadata[0]["input"] == str(plaintext)
    assert output_metadata[0]["output"] == str(ciphertext)
    assert "header_auth" not in output_metadata[0]
    assert not decrypted.isfile()
    assert "not allowed by this Master Key Provider" in message


def test_cycle_discovery_true_filter_correct(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    metadata = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template(metadata=True).format(
        source=str(plaintext), target=str(ciphertext), metadata="--metadata-output " + str(metadata)
    )
    decrypt_args = decrypt_args_template(metadata=True).format(
        source=str(ciphertext), target=str(decrypted), metadata="--metadata-output " + str(metadata)
    )
    arn = cmk_arn_value().split(":")
    account = arn[4]
    partition = arn[1]
    decrypt_args += " -w discovery=true discovery-account={account} discovery-partition={partition}".format(
        account=account, partition=partition
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    output_metadata = [json.loads(line) for line in metadata.readlines()]
    for line in output_metadata:
        for key, value in (("a", "b"), ("c", "d")):
            assert line["header"]["encryption_context"][key] == value

    assert output_metadata[0]["mode"] == "encrypt"
    assert output_metadata[0]["input"] == str(plaintext)
    assert output_metadata[0]["output"] == str(ciphertext)
    assert "header_auth" not in output_metadata[0]
    assert output_metadata[1]["mode"] == "decrypt"
    assert output_metadata[1]["input"] == str(ciphertext)
    assert output_metadata[1]["output"] == str(decrypted)
    assert "header_auth" in output_metadata[1]


def test_cycle_discovery_true_filter_multiple_accounts_correct(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    metadata = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template(metadata=True).format(
        source=str(plaintext), target=str(ciphertext), metadata="--metadata-output " + str(metadata)
    )
    decrypt_args = decrypt_args_template(metadata=True).format(
        source=str(ciphertext), target=str(decrypted), metadata="--metadata-output " + str(metadata)
    )
    arn = cmk_arn_value().split(":")
    account = arn[4]
    partition = arn[1]
    decrypt_args += (
        " -w discovery=true discovery-account=123 discovery-account={account} discovery-partition={partition}".format(
            account=account, partition=partition
        )
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    output_metadata = [json.loads(line) for line in metadata.readlines()]
    for line in output_metadata:
        for key, value in (("a", "b"), ("c", "d")):
            assert line["header"]["encryption_context"][key] == value

    assert output_metadata[0]["mode"] == "encrypt"
    assert output_metadata[0]["input"] == str(plaintext)
    assert output_metadata[0]["output"] == str(ciphertext)
    assert "header_auth" not in output_metadata[0]
    assert output_metadata[1]["mode"] == "decrypt"
    assert output_metadata[1]["input"] == str(ciphertext)
    assert output_metadata[1]["output"] == str(decrypted)
    assert "header_auth" in output_metadata[1]


def test_cycle_discovery_false(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    metadata = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template(metadata=True).format(
        source=str(plaintext), target=str(ciphertext), metadata="--metadata-output " + str(metadata)
    )
    decrypt_args = decrypt_args_template(metadata=True, discovery=False).format(
        source=str(ciphertext), target=str(decrypted), metadata="--metadata-output " + str(metadata)
    )
    decrypt_args += " -w discovery=false key=" + cmk_arn_value()

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    output_metadata = [json.loads(line) for line in metadata.readlines()]
    for line in output_metadata:
        for key, value in (("a", "b"), ("c", "d")):
            assert line["header"]["encryption_context"][key] == value

    assert output_metadata[0]["mode"] == "encrypt"
    assert output_metadata[0]["input"] == str(plaintext)
    assert output_metadata[0]["output"] == str(ciphertext)
    assert "header_auth" not in output_metadata[0]
    assert output_metadata[1]["mode"] == "decrypt"
    assert output_metadata[1]["input"] == str(ciphertext)
    assert output_metadata[1]["output"] == str(decrypted)
    assert "header_auth" in output_metadata[1]


def test_cycle_discovery_false_wrong_key_id(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    metadata = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template(metadata=True).format(
        source=str(plaintext), target=str(ciphertext), metadata="--metadata-output " + str(metadata)
    )
    decrypt_args = decrypt_args_template(metadata=True, discovery=False).format(
        source=str(ciphertext), target=str(decrypted), metadata="--metadata-output " + str(metadata)
    )
    wrong_key = cmk_arn_value()[:-1]
    decrypt_args += " -w discovery=false key=" + wrong_key

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    message = aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    output_metadata = [json.loads(line) for line in metadata.readlines()]
    for line in output_metadata:
        for key, value in (("a", "b"), ("c", "d")):
            assert line["header"]["encryption_context"][key] == value

    assert output_metadata[0]["mode"] == "encrypt"
    assert output_metadata[0]["input"] == str(plaintext)
    assert output_metadata[0]["output"] == str(ciphertext)
    assert "header_auth" not in output_metadata[0]
    assert not decrypted.isfile()
    assert "Unable to decrypt any data key" in message


def test_cycle_decrypt_unsigned_success(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    metadata = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template(metadata=True).format(
        source=str(plaintext), target=str(ciphertext), metadata="--metadata-output " + str(metadata)
    )
    # Use an unsigned algorithm for encryption
    encrypt_args += " --algorithm AES_256_GCM_HKDF_SHA512_COMMIT_KEY"
    decrypt_args = decrypt_unsigned_args_template(metadata=True).format(
        source=str(ciphertext), target=str(decrypted), metadata="--metadata-output " + str(metadata)
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    output_metadata = [json.loads(line) for line in metadata.readlines()]
    for line in output_metadata:
        for key, value in (("a", "b"), ("c", "d")):
            assert line["header"]["encryption_context"][key] == value

    assert output_metadata[0]["mode"] == "encrypt"
    assert output_metadata[0]["input"] == str(plaintext)
    assert output_metadata[0]["output"] == str(ciphertext)
    assert "header_auth" not in output_metadata[0]
    assert output_metadata[1]["mode"] == "decrypt-unsigned"
    assert output_metadata[1]["input"] == str(ciphertext)
    assert output_metadata[1]["output"] == str(decrypted)
    assert "header_auth" in output_metadata[1]


def test_cycle_decrypt_unsigned_fails_on_signed_message(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    metadata = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template(metadata=True).format(
        source=str(plaintext), target=str(ciphertext), metadata="--metadata-output " + str(metadata)
    )
    # Use a signed algorithm for encryption
    encrypt_args += " --algorithm AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384"
    decrypt_args = decrypt_unsigned_args_template(metadata=True).format(
        source=str(ciphertext), target=str(decrypted), metadata="--metadata-output " + str(metadata)
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    message = aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    output_metadata = [json.loads(line) for line in metadata.readlines()]
    for line in output_metadata:
        for key, value in (("a", "b"), ("c", "d")):
            assert line["header"]["encryption_context"][key] == value

    assert output_metadata[0]["mode"] == "encrypt"
    assert output_metadata[0]["input"] == str(plaintext)
    assert output_metadata[0]["output"] == str(ciphertext)
    assert "header_auth" not in output_metadata[0]
    assert not decrypted.isfile()
    assert "Cannot decrypt signed message in decrypt-unsigned mode" in message


@pytest.mark.parametrize(
    "max_encrypted_data_keys, is_valid",
    (
        (1, True),
        (10, True),
        (2 ** 16 - 1, True),
        (2 ** 16, True),
        (0, False),
        (-1, False),
    ),
)
def test_max_encrypted_data_key_valid_values(tmpdir, max_encrypted_data_keys, is_valid):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    encrypt_args += " --max-encrypted-data-keys {}".format(max_encrypted_data_keys)
    message = aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    if is_valid:
        assert message is None
    else:
        assert "max_encrypted_data_keys cannot be less than 1" in message


@pytest.mark.parametrize("num_keys", (2, 3))
def test_cycle_within_max_encrypted_data_keys(tmpdir, num_keys):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")

    extra_key_arg = " -w key={}".format(cmk_arn_value())
    max_edks_arg = " --max-encrypted-data-keys {}".format(3)

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    encrypt_args += max_edks_arg
    encrypt_args += extra_key_arg * (num_keys - 1)
    message = aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    assert message is None

    decrypt_args = decrypt_args_template().format(source=str(ciphertext), target=str(decrypted))
    decrypt_args += max_edks_arg
    message = aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))
    assert message is None


def test_encrypt_over_max_encrypted_data_keys(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")

    extra_key_arg = " -w key={}".format(cmk_arn_value())
    max_edks_arg = " --max-encrypted-data-keys {}".format(3)

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    encrypt_args += max_edks_arg
    encrypt_args += extra_key_arg * 3
    message = aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    assert message is not None
    assert "MaxEncryptedDataKeysExceeded" in message
    assert "Number of encrypted data keys found larger than configured value" in message


def test_decrypt_over_max_encrypted_data_keys(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")

    extra_key_arg = " -w key={}".format(cmk_arn_value())
    max_edks_arg = " --max-encrypted-data-keys {}".format(3)

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    encrypt_args += extra_key_arg * 3
    message = aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    assert message is None

    decrypt_args = decrypt_args_template().format(source=str(ciphertext), target=str(decrypted))
    decrypt_args += max_edks_arg
    message = aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))
    assert message is not None
    assert "MaxEncryptedDataKeysExceeded" in message
    assert "Number of encrypted data keys found larger than configured value" in message


@pytest.mark.parametrize("required_encryption_context", ("a", "c", "a c", "a=b", "a=b c", "c=d", "a c=d", "a=b c=d"))
def test_file_to_file_decrypt_required_encryption_context_success(tmpdir, required_encryption_context):
    plaintext = tmpdir.join("source_plaintext")
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    with open(str(plaintext), "wb") as f:
        f.write(os.urandom(1024))

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    decrypt_args = (
        decrypt_args_template().format(source=str(ciphertext), target=str(decrypted))
        + " --encryption-context "
        + required_encryption_context
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    assert filecmp.cmp(str(plaintext), str(decrypted))


@pytest.mark.parametrize("required_encryption_context", ("a", "c", "a c", "a=b", "a=b c", "c=d", "a c=d", "a=b c=d"))
def test_file_to_file_decrypt_unsigned_required_encryption_context_success(tmpdir, required_encryption_context):
    plaintext = tmpdir.join("source_plaintext")
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    with open(str(plaintext), "wb") as f:
        f.write(os.urandom(1024))

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    # Use an unsigned algorithm for encryption
    encrypt_args += " --algorithm AES_256_GCM_HKDF_SHA512_COMMIT_KEY"
    decrypt_args = (
        decrypt_unsigned_args_template().format(source=str(ciphertext), target=str(decrypted))
        + " --encryption-context "
        + required_encryption_context
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    assert filecmp.cmp(str(plaintext), str(decrypted))


@pytest.mark.parametrize("required_encryption_context", ("a=VALUE_NOT_FOUND", "KEY_NOT_FOUND"))
def test_file_to_file_decrypt_required_encryption_context_fail(tmpdir, required_encryption_context):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    metadata_file = tmpdir.join("metadata")
    decrypted = tmpdir.join("decrypted")

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    decrypt_args = (
        decrypt_args_template(metadata=True).format(
            source=str(ciphertext), target=str(decrypted), metadata=" --metadata-output " + str(metadata_file)
        )
        + " --encryption-context "
        + required_encryption_context
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    assert not decrypted.isfile()
    raw_metadata = metadata_file.read()
    parsed_metadata = json.loads(raw_metadata)
    assert parsed_metadata["skipped"]
    assert parsed_metadata["reason"] == "Missing encryption context key or value"


@pytest.mark.parametrize("required_encryption_context", ("a=VALUE_NOT_FOUND", "KEY_NOT_FOUND"))
def test_file_to_file_decrypt_unsigned_required_encryption_context_fail(tmpdir, required_encryption_context):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    metadata_file = tmpdir.join("metadata")
    decrypted = tmpdir.join("decrypted")

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    # Use an unsigned algorithm for encryption
    encrypt_args += " --algorithm AES_256_GCM_HKDF_SHA512_COMMIT_KEY"
    decrypt_args = (
        decrypt_unsigned_args_template(metadata=True).format(
            source=str(ciphertext), target=str(decrypted), metadata=" --metadata-output " + str(metadata_file)
        )
        + " --encryption-context "
        + required_encryption_context
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    assert not decrypted.isfile()
    raw_metadata = metadata_file.read()
    parsed_metadata = json.loads(raw_metadata)
    assert parsed_metadata["skipped"]
    assert parsed_metadata["reason"] == "Missing encryption context key or value"


def test_file_to_file_cycle(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    with open(str(plaintext), "wb") as f:
        f.write(os.urandom(1024))

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    decrypt_args = decrypt_args_template().format(source=str(ciphertext), target=str(decrypted))

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    assert filecmp.cmp(str(plaintext), str(decrypted))


# This test may result in a false positive if the input is not large enough
# Note that test_file_to_stdout_decrypt_buffer_output_with_failure helps confirm this is not a false positive
@pytest.mark.skipif(not aws_encryption_cli_is_findable(), reason="aws-encryption-cli executable could not be found.")
def test_file_to_stdout_decrypt_buffer_output_with_failure(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    # Use an input large enough that results in processing in several chunks
    plaintext.write_binary(os.urandom(16384))
    ciphertext = tmpdir.join("ciphertext")

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    decrypt_args = "aws-encryption-cli " + decrypt_args_template(buffer=True).format(source=str(ciphertext), target="-")

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))

    # Tamper with encryption result to get an error on decrypt
    with open(str(ciphertext), "rb+") as f:
        f.seek(-1, os.SEEK_END)
        f.truncate()

    # pylint: disable=consider-using-with
    proc = Popen(shlex.split(decrypt_args, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    decrypted_output, stderr = proc.communicate()

    # Verify that no output was written
    assert decrypted_output == b""
    assert b"Encountered unexpected error" in stderr
    # Verify the no exception was raised trying to delete verifiable non-existant "-" file,
    # to verify that we did not attempt to do that
    assert b"OSError" not in stderr  # Python 2
    assert b"FileNotFoundError" not in stderr  # Python 3


# This test may result in a false negative if the input is not large enough
# Note that this test helps confirm that test_file_to_stdout_decrypt_buffer_output_with_failure is not a false positive
@pytest.mark.skipif(not aws_encryption_cli_is_findable(), reason="aws-encryption-cli executable could not be found.")
def test_file_to_stdout_decrypt_no_buffering_with_failure(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    # Use an input large enough that results in processing in several chunks
    plaintext.write_binary(os.urandom(16384))
    ciphertext = tmpdir.join("ciphertext")

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    decrypt_args = "aws-encryption-cli " + decrypt_args_template(buffer=False).format(
        source=str(ciphertext), target="-"
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))

    # Tamper with encryption result to get an error on decrypt
    with open(str(ciphertext), "rb+") as f:
        f.seek(-1, os.SEEK_END)
        f.truncate()

    # pylint: disable=consider-using-with
    proc = Popen(shlex.split(decrypt_args, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    decrypted_output, stderr = proc.communicate()

    # Verify that output was not buffered and some output was written to stout
    assert len(decrypted_output) > 0
    assert b"Encountered unexpected error" in stderr
    # Verify the no exception was raised trying to delete verifiable non-existant "-" file,
    # to verify that we did not attempt to do that
    assert b"OSError" not in stderr  # Python 2
    assert b"FileNotFoundError" not in stderr  # Python 3


@pytest.mark.skipif(is_windows(), reason=WINDOWS_SKIP_MESSAGE)
def test_file_to_file_cycle_target_through_symlink(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    output_dir = tmpdir.mkdir("output")
    os.symlink(str(output_dir), str(tmpdir.join("output_link")))
    ciphertext = tmpdir.join("output_link", "ciphertext")
    decrypted = tmpdir.join("decrypted")
    with open(str(plaintext), "wb") as f:
        f.write(os.urandom(1024))

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    decrypt_args = decrypt_args_template().format(source=str(ciphertext), target=str(decrypted))

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    assert filecmp.cmp(str(plaintext), str(decrypted))


@pytest.mark.parametrize("encode, decode", ((True, False), (False, True), (True, True), (False, False)))
def test_file_to_file_base64(tmpdir, encode, decode):
    plaintext = tmpdir.join("source_plaintext")
    ciphertext_a = tmpdir.join("ciphertext-a")
    ciphertext_b = tmpdir.join("ciphertext-b")
    decrypted = tmpdir.join("decrypted")
    plaintext_source = os.urandom(10240)  # make sure we have more than one chunk
    with open(str(plaintext), "wb") as f:
        f.write(plaintext_source)

    encrypt_flag = " --encode" if encode else ""
    decrypt_flag = " --decode" if decode else ""

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext_a)) + encrypt_flag
    decrypt_args = decrypt_args_template().format(source=str(ciphertext_b), target=str(decrypted)) + decrypt_flag

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))

    if encode and not decode:
        with open(str(ciphertext_a), "rb") as ct_a, open(str(ciphertext_b), "wb") as ct_b:
            raw_ct = base64.b64decode(ct_a.read())
            ct_b.write(raw_ct)
    elif decode and not encode:
        with open(str(ciphertext_a), "rb") as ct, open(str(ciphertext_b), "wb") as b64_ct:
            b64_ct.write(base64.b64encode(ct.read()))
    else:
        shutil.copy2(str(ciphertext_a), str(ciphertext_b))

    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    with open(str(decrypted), "rb") as f:
        decrypted_plaintext = f.read()

    assert decrypted_plaintext == plaintext_source


def test_file_to_file_cycle_with_caching(tmpdir):
    plaintext = tmpdir.join("source_plaintext")
    ciphertext = tmpdir.join("ciphertext")
    decrypted = tmpdir.join("decrypted")
    with open(str(plaintext), "wb") as f:
        f.write(os.urandom(1024))

    encrypt_args = encrypt_args_template(caching=True).format(source=str(plaintext), target=str(ciphertext))
    decrypt_args = decrypt_args_template().format(source=str(ciphertext), target=str(decrypted))

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    assert filecmp.cmp(str(plaintext), str(decrypted))


def test_file_overwrite_source_file_to_file_custom_empty_prefix(tmpdir):
    plaintext_source = os.urandom(2014)
    plaintext = tmpdir.join("source_plaintext")
    with open(str(plaintext), "wb") as f:
        f.write(plaintext_source)

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(plaintext)) + " --suffix"

    test_result = aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))

    assert test_result == "Destination and source cannot be the same"

    with open(str(plaintext), "rb") as f:
        assert f.read() == plaintext_source


def test_file_overwrite_source_dir_to_dir_custom_empty_prefix(tmpdir):
    plaintext_source = os.urandom(2014)
    plaintext = tmpdir.join("source_plaintext")
    with open(str(plaintext), "wb") as f:
        f.write(plaintext_source)

    encrypt_args = encrypt_args_template().format(source=str(tmpdir), target=str(tmpdir)) + " --suffix"

    test_result = aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))

    assert test_result == "Destination and source cannot be the same"

    with open(str(plaintext), "rb") as f:
        assert f.read() == plaintext_source


def test_file_overwrite_source_file_to_dir_custom_empty_prefix(tmpdir):
    plaintext_source = os.urandom(2014)
    plaintext = tmpdir.join("source_plaintext")
    with open(str(plaintext), "wb") as f:
        f.write(plaintext_source)

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(tmpdir)) + " --suffix"

    test_result = aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))

    assert test_result is None

    with open(str(plaintext), "rb") as f:
        assert f.read() == plaintext_source


def test_file_to_dir_cycle(tmpdir):
    inner_dir = tmpdir.mkdir("inner")
    plaintext = tmpdir.join("source_plaintext")
    ciphertext = inner_dir.join("source_plaintext.encrypted")
    decrypted = tmpdir.join("decrypted")
    with open(str(plaintext), "wb") as f:
        f.write(os.urandom(1024))

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(inner_dir))
    decrypt_args = decrypt_args_template().format(source=str(ciphertext), target=str(decrypted))

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    assert os.path.isfile(str(ciphertext))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    assert filecmp.cmp(str(plaintext), str(decrypted))


@pytest.mark.skipif(not aws_encryption_cli_is_findable(), reason="aws-encryption-cli executable could not be found.")
def test_stdin_to_file_to_stdout_cycle(tmpdir):
    ciphertext_file = tmpdir.join("ciphertext")
    plaintext = os.urandom(1024)

    encrypt_args = "aws-encryption-cli " + encrypt_args_template(decode=True).format(
        source="-", target=str(ciphertext_file)
    )
    decrypt_args = "aws-encryption-cli " + decrypt_args_template(encode=True).format(
        source=str(ciphertext_file), target="-"
    )

    # For each use of Popen in tests: it only supports use as a resource in `with` statements as of Python 3.4,
    # so we can't use that unconditionally yet.
    # pylint: disable=consider-using-with
    proc = Popen(shlex.split(encrypt_args, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    _stdout, _stderr = proc.communicate(input=base64.b64encode(plaintext))

    # pylint: disable=consider-using-with
    proc = Popen(shlex.split(decrypt_args, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    decrypted_stdout, _stderr = proc.communicate()

    assert base64.b64decode(decrypted_stdout) == plaintext


@pytest.mark.skipif(not aws_encryption_cli_is_findable(), reason="aws-encryption-cli executable could not be found.")
def test_stdin_stdout_stdin_stdout_cycle():
    plaintext = os.urandom(1024)

    encrypt_args = "aws-encryption-cli " + encrypt_args_template(decode=True, encode=True).format(
        source="-", target="-"
    )
    decrypt_args = "aws-encryption-cli " + decrypt_args_template(decode=True, encode=True).format(
        source="-", target="-"
    )
    # pylint: disable=consider-using-with
    proc = Popen(shlex.split(encrypt_args, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    ciphertext, _stderr = proc.communicate(input=base64.b64encode(plaintext))
    # pylint: disable=consider-using-with
    proc = Popen(shlex.split(decrypt_args, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    decrypted_stdout, _stderr = proc.communicate(input=ciphertext)

    assert base64.b64decode(decrypted_stdout) == plaintext


@pytest.mark.skipif(not aws_encryption_cli_is_findable(), reason="aws-encryption-cli executable could not be found.")
@pytest.mark.parametrize("required_encryption_context", ("a=VALUE_NOT_FOUND", "KEY_NOT_FOUND"))
def test_file_to_stdout_decrypt_required_encryption_context_fail(tmpdir, required_encryption_context):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    metadata_file = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    decrypt_args = (
        "aws-encryption-cli "
        + decrypt_args_template(metadata=True).format(
            source=str(ciphertext), target="-", metadata=" --metadata-output " + str(metadata_file)
        )
        + " --encryption-context "
        + required_encryption_context
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    # pylint: disable=consider-using-with
    proc = Popen(shlex.split(decrypt_args, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    decrypted_output, stderr = proc.communicate()

    # Verify that no output was written
    assert decrypted_output == b""
    # Verify the no exception was raised trying to delete verifiable non-existant "-" file,
    # to verify that we did not attempt to do that
    assert b"OSError" not in stderr  # Python 2
    assert b"FileNotFoundError" not in stderr  # Python 3
    raw_metadata = metadata_file.read()
    parsed_metadata = json.loads(raw_metadata)
    assert parsed_metadata["output"] == "<stdout>"
    assert parsed_metadata["skipped"]
    assert parsed_metadata["reason"] == "Missing encryption context key or value"


@pytest.mark.skipif(not aws_encryption_cli_is_findable(), reason="aws-encryption-cli executable could not be found.")
@pytest.mark.parametrize("required_encryption_context", ("a=VALUE_NOT_FOUND", "KEY_NOT_FOUND"))
def test_file_to_stdout_decrypt_unsigned_required_encryption_context_fail(tmpdir, required_encryption_context):
    plaintext = tmpdir.join("source_plaintext")
    plaintext.write_binary(os.urandom(1024))
    ciphertext = tmpdir.join("ciphertext")
    metadata_file = tmpdir.join("metadata")

    encrypt_args = encrypt_args_template().format(source=str(plaintext), target=str(ciphertext))
    # Use an unsigned algorithm for encryption
    encrypt_args += " --algorithm AES_256_GCM_HKDF_SHA512_COMMIT_KEY"
    decrypt_args = (
        "aws-encryption-cli "
        + decrypt_unsigned_args_template(metadata=True).format(
            source=str(ciphertext), target="-", metadata=" --metadata-output " + str(metadata_file)
        )
        + " --encryption-context "
        + required_encryption_context
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    # pylint: disable=consider-using-with
    proc = Popen(shlex.split(decrypt_args, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    decrypted_output, stderr = proc.communicate()
    # Verify that no output was written
    assert decrypted_output == b""
    # Verify the no exception was raised trying to delete verifiable non-existant "-" file,
    # to verify that we did not attempt to do that
    assert b"OSError" not in stderr  # Python 2
    assert b"FileNotFoundError" not in stderr  # Python 3
    raw_metadata = metadata_file.read()
    parsed_metadata = json.loads(raw_metadata)
    assert parsed_metadata["output"] == "<stdout>"
    assert parsed_metadata["skipped"]
    assert parsed_metadata["reason"] == "Missing encryption context key or value"


def test_dir_to_dir_cycle(tmpdir):
    plaintext_dir = tmpdir.mkdir("plaintext")
    ciphertext_dir = tmpdir.mkdir("ciphertext")
    decrypted_dir = tmpdir.mkdir("decrypted")
    plaintext_dir.mkdir("a").mkdir("b")
    plaintext_dir.mkdir("c")
    for source_file_path in (["1"], ["a", "2"], ["a", "b", "3"], ["c", "4"]):
        with open(os.path.join(str(plaintext_dir), *source_file_path), "wb") as file:
            file.write(os.urandom(1024))

    encrypt_args = encrypt_args_template().format(source=str(plaintext_dir), target=str(ciphertext_dir)) + " -r"
    decrypt_args = decrypt_args_template().format(source=str(ciphertext_dir), target=str(decrypted_dir)) + " -r"

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    for base_dir, _dirs, filenames in os.walk(str(plaintext_dir)):
        for file in filenames:
            plaintext_filename = os.path.join(base_dir, file)
            decrypted_filename = (
                plaintext_filename.replace(str(plaintext_dir), str(decrypted_dir)) + ".encrypted.decrypted"
            )
            assert filecmp.cmp(plaintext_filename, decrypted_filename)


def test_dir_to_dir_cycle_custom_suffix(tmpdir):
    plaintext_dir = tmpdir.mkdir("plaintext")
    ciphertext_dir = tmpdir.mkdir("ciphertext")
    decrypted_dir = tmpdir.mkdir("decrypted")
    plaintext_dir.mkdir("a").mkdir("b")
    plaintext_dir.mkdir("c")
    for source_file_path in (["1"], ["a", "2"], ["a", "b", "3"], ["c", "4"]):
        with open(os.path.join(str(plaintext_dir), *source_file_path), "wb") as file:
            file.write(os.urandom(1024))

    encrypt_suffix = "THIS_IS_A_CUSTOM_SUFFIX"
    encrypt_args = (
        encrypt_args_template().format(source=str(plaintext_dir), target=str(ciphertext_dir))
        + " -r"
        + " --suffix "
        + encrypt_suffix
    )
    decrypt_suffix = ".anotherSuffix"
    decrypt_args = (
        decrypt_args_template().format(source=str(ciphertext_dir), target=str(decrypted_dir))
        + " -r"
        + " --suffix "
        + decrypt_suffix
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    for base_dir, _dirs, filenames in os.walk(str(plaintext_dir)):
        for file in filenames:
            plaintext_filename = os.path.join(base_dir, file)
            decrypted_filename = (
                plaintext_filename.replace(str(plaintext_dir), str(decrypted_dir)) + encrypt_suffix + decrypt_suffix
            )
            assert filecmp.cmp(plaintext_filename, decrypted_filename)


def test_glob_to_dir_cycle(tmpdir):
    plaintext_dir = tmpdir.mkdir("plaintext")
    ciphertext_dir = tmpdir.mkdir("ciphertext")
    decrypted_dir = tmpdir.mkdir("decrypted")
    for source_file_path in ("a.1", "b.2", "b.1", "c.1"):
        with open(os.path.join(str(plaintext_dir), source_file_path), "wb") as file:
            file.write(os.urandom(1024))

    suffix = ".1"

    encrypt_args = (
        encrypt_args_template().format(
            source=os.path.join(str(plaintext_dir), "*" + suffix), target=str(ciphertext_dir)
        )
        + " -r"
    )
    decrypt_args = decrypt_args_template().format(source=str(ciphertext_dir), target=str(decrypted_dir)) + " -r"

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args, posix=not is_windows()))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args, posix=not is_windows()))

    for base_dir, _dirs, filenames in os.walk(str(plaintext_dir)):
        for file in filenames:
            plaintext_filename = os.path.join(base_dir, file)
            decrypted_filename = (
                plaintext_filename.replace(str(plaintext_dir), str(decrypted_dir)) + ".encrypted.decrypted"
            )

            if plaintext_filename.endswith(suffix):
                assert filecmp.cmp(plaintext_filename, decrypted_filename)
            else:
                assert not os.path.isfile(decrypted_filename)
