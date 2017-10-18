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
from distutils.spawn import find_executable
import filecmp
import os
import shlex
from subprocess import PIPE, Popen

import pytest

import aws_encryption_sdk_cli

ENABLE_TESTS_FLAG = 'AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_CONTROL'
HERE = os.path.abspath(os.path.dirname(__file__))
CONFIG_FILE_NAME = os.path.join(HERE, 'integration_tests.conf')
ENCRYPT_ARGS_TEMPLATE = '-e -i {source} -o {target} --encryption-context a=b c=d @' + CONFIG_FILE_NAME
DECRYPT_ARGS_TEMPLATE = '-d -i {source} -o {target} @' + CONFIG_FILE_NAME
CACHING_CONFIG = ' --caching capacity=10 max_age=60.0'


def _should_run_tests():
    return os.environ.get(ENABLE_TESTS_FLAG, None) == 'RUN'


def _aws_crypto_is_findable():
    path = find_executable('aws-crypto')
    if path is None:
        UserWarning('aws-crypto executable could not be found')
        return False
    return True


@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_file_to_file_cycle(tmpdir):
    plaintext = tmpdir.join('source_plaintext')
    ciphertext = tmpdir.join('ciphertext')
    decrypted = tmpdir.join('decrypted')
    with open(str(plaintext), 'wb') as f:
        f.write(os.urandom(1024))

    encrypt_args = ENCRYPT_ARGS_TEMPLATE.format(
        source=str(plaintext),
        target=str(ciphertext)
    )
    decrypt_args = DECRYPT_ARGS_TEMPLATE.format(
        source=str(ciphertext),
        target=str(decrypted)
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args))

    assert filecmp.cmp(str(plaintext), str(decrypted))


@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_file_to_file_cycle_with_caching(tmpdir):
    plaintext = tmpdir.join('source_plaintext')
    ciphertext = tmpdir.join('ciphertext')
    decrypted = tmpdir.join('decrypted')
    with open(str(plaintext), 'wb') as f:
        f.write(os.urandom(1024))

    encrypt_args = ENCRYPT_ARGS_TEMPLATE.format(
        source=str(plaintext),
        target=str(ciphertext)
    ) + CACHING_CONFIG
    decrypt_args = DECRYPT_ARGS_TEMPLATE.format(
        source=str(ciphertext),
        target=str(decrypted)
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args))

    assert filecmp.cmp(str(plaintext), str(decrypted))


@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_file_overwrite_source_file_to_file_custom_empty_prefix(tmpdir):
    plaintext_source = os.urandom(2014)
    plaintext = tmpdir.join('source_plaintext')
    with open(str(plaintext), 'wb') as f:
        f.write(plaintext_source)

    encrypt_args = ENCRYPT_ARGS_TEMPLATE.format(
        source=str(plaintext),
        target=str(plaintext)
    ) + ' --suffix'

    test_result = aws_encryption_sdk_cli.cli(shlex.split(encrypt_args))

    assert test_result == 'Destination and source cannot be the same'

    with open(str(plaintext), 'rb') as f:
        assert f.read() == plaintext_source


@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_file_overwrite_source_dir_to_dir_custom_empty_prefix(tmpdir):
    plaintext_source = os.urandom(2014)
    plaintext = tmpdir.join('source_plaintext')
    with open(str(plaintext), 'wb') as f:
        f.write(plaintext_source)

    encrypt_args = ENCRYPT_ARGS_TEMPLATE.format(
        source=str(tmpdir),
        target=str(tmpdir)
    ) + ' --suffix'

    test_result = aws_encryption_sdk_cli.cli(shlex.split(encrypt_args))

    assert test_result == 'Destination and source cannot be the same'

    with open(str(plaintext), 'rb') as f:
        assert f.read() == plaintext_source


@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_file_overwrite_source_file_to_dir_custom_empty_prefix(tmpdir):
    plaintext_source = os.urandom(2014)
    plaintext = tmpdir.join('source_plaintext')
    with open(str(plaintext), 'wb') as f:
        f.write(plaintext_source)

    encrypt_args = ENCRYPT_ARGS_TEMPLATE.format(
        source=str(plaintext),
        target=str(tmpdir)
    ) + ' --suffix'

    test_result = aws_encryption_sdk_cli.cli(shlex.split(encrypt_args))

    assert test_result == 'Destination and source cannot be the same'

    with open(str(plaintext), 'rb') as f:
        assert f.read() == plaintext_source


@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_file_to_dir_cycle(tmpdir):
    inner_dir = tmpdir.mkdir('inner')
    plaintext = tmpdir.join('source_plaintext')
    ciphertext = inner_dir.join('source_plaintext.encrypted')
    decrypted = tmpdir.join('decrypted')
    with open(str(plaintext), 'wb') as f:
        f.write(os.urandom(1024))

    encrypt_args = ENCRYPT_ARGS_TEMPLATE.format(
        source=str(plaintext),
        target=str(inner_dir)
    )
    decrypt_args = DECRYPT_ARGS_TEMPLATE.format(
        source=str(ciphertext),
        target=str(decrypted)
    )

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args))
    assert os.path.isfile(str(ciphertext))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args))

    assert filecmp.cmp(str(plaintext), str(decrypted))


@pytest.mark.skipif(not _aws_crypto_is_findable(), reason='aws-crypto executable could not be found.')
@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_stdin_to_file_to_stdout_cycle(tmpdir):
    ciphertext_file = tmpdir.join('ciphertext')
    plaintext = os.urandom(1024)

    encrypt_args = 'aws-crypto ' + ENCRYPT_ARGS_TEMPLATE.format(
        source='-',
        target=str(ciphertext_file)
    )
    decrypt_args = 'aws-crypto ' + DECRYPT_ARGS_TEMPLATE.format(
        source=str(ciphertext_file),
        target='-'
    )

    proc = Popen(shlex.split(encrypt_args), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    _stdout, _stderr = proc.communicate(input=plaintext)

    proc = Popen(shlex.split(decrypt_args), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    decrypted_stdout, _stderr = proc.communicate()

    assert decrypted_stdout == plaintext


@pytest.mark.skipif(not _aws_crypto_is_findable(), reason='aws-crypto executable could not be found.')
@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_stdin_stdout_stdin_stdout_cycle():
    plaintext = os.urandom(1024)

    encrypt_args = 'aws-crypto ' + ENCRYPT_ARGS_TEMPLATE.format(
        source='-',
        target='-'
    )
    decrypt_args = 'aws-crypto ' + DECRYPT_ARGS_TEMPLATE.format(
        source='-',
        target='-'
    )
    proc = Popen(shlex.split(encrypt_args), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    ciphertext, _stderr = proc.communicate(input=plaintext)
    proc = Popen(shlex.split(decrypt_args), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    decrypted_stdout, _stderr = proc.communicate(input=ciphertext)

    assert decrypted_stdout == plaintext


@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_dir_to_dir_cycle(tmpdir):
    plaintext_dir = tmpdir.mkdir('plaintext')
    ciphertext_dir = tmpdir.mkdir('ciphertext')
    decrypted_dir = tmpdir.mkdir('decrypted')
    plaintext_dir.mkdir('a').mkdir('b')
    plaintext_dir.mkdir('c')
    for source_file_path in (['1'], ['a', '2'], ['a', 'b', '3'], ['c', '4']):
        with open(os.path.join(str(plaintext_dir), *source_file_path), 'wb') as file:
            file.write(os.urandom(1024))

    encrypt_args = ENCRYPT_ARGS_TEMPLATE.format(
        source=str(plaintext_dir),
        target=str(ciphertext_dir)
    ) + ' -r'
    decrypt_args = DECRYPT_ARGS_TEMPLATE.format(
        source=str(ciphertext_dir),
        target=str(decrypted_dir)
    ) + ' -r'

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args))

    for base_dir, _dirs, filenames in os.walk(str(plaintext_dir)):
        for file in filenames:
            plaintext_filename = os.path.join(base_dir, file)
            decrypted_filename = plaintext_filename.replace(
                str(plaintext_dir),
                str(decrypted_dir)
            ) + '.encrypted.decrypted'
            assert filecmp.cmp(plaintext_filename, decrypted_filename)


@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_dir_to_dir_cycle_custom_suffix(tmpdir):
    plaintext_dir = tmpdir.mkdir('plaintext')
    ciphertext_dir = tmpdir.mkdir('ciphertext')
    decrypted_dir = tmpdir.mkdir('decrypted')
    plaintext_dir.mkdir('a').mkdir('b')
    plaintext_dir.mkdir('c')
    for source_file_path in (['1'], ['a', '2'], ['a', 'b', '3'], ['c', '4']):
        with open(os.path.join(str(plaintext_dir), *source_file_path), 'wb') as file:
            file.write(os.urandom(1024))

    encrypt_suffix = 'THIS_IS_A_CUSTOM_SUFFIX'
    encrypt_args = ENCRYPT_ARGS_TEMPLATE.format(
        source=str(plaintext_dir),
        target=str(ciphertext_dir)
    ) + ' -r' + ' --suffix ' + encrypt_suffix
    decrypt_suffix = '.anotherSuffix'
    decrypt_args = DECRYPT_ARGS_TEMPLATE.format(
        source=str(ciphertext_dir),
        target=str(decrypted_dir)
    ) + ' -r' + ' --suffix ' + decrypt_suffix

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args))

    for base_dir, _dirs, filenames in os.walk(str(plaintext_dir)):
        for file in filenames:
            plaintext_filename = os.path.join(base_dir, file)
            decrypted_filename = plaintext_filename.replace(
                str(plaintext_dir),
                str(decrypted_dir)
            ) + encrypt_suffix + decrypt_suffix
            assert filecmp.cmp(plaintext_filename, decrypted_filename)


@pytest.mark.skipif(not _should_run_tests(), reason='Integration tests disabled. See test/integration/README.rst')
def test_glob_to_dir_cycle(tmpdir):
    plaintext_dir = tmpdir.mkdir('plaintext')
    ciphertext_dir = tmpdir.mkdir('ciphertext')
    decrypted_dir = tmpdir.mkdir('decrypted')
    for source_file_path in ('a.1', 'b.2', 'b.1', 'c.1'):
        with open(os.path.join(str(plaintext_dir), source_file_path), 'wb') as file:
            file.write(os.urandom(1024))

    suffix = '.1'

    encrypt_args = ENCRYPT_ARGS_TEMPLATE.format(
        source=os.path.join(str(plaintext_dir), '*' + suffix),
        target=str(ciphertext_dir)
    ) + ' -r'
    decrypt_args = DECRYPT_ARGS_TEMPLATE.format(
        source=str(ciphertext_dir),
        target=str(decrypted_dir)
    ) + ' -r'

    aws_encryption_sdk_cli.cli(shlex.split(encrypt_args))
    aws_encryption_sdk_cli.cli(shlex.split(decrypt_args))

    for base_dir, _dirs, filenames in os.walk(str(plaintext_dir)):
        for file in filenames:
            plaintext_filename = os.path.join(base_dir, file)
            decrypted_filename = plaintext_filename.replace(
                str(plaintext_dir),
                str(decrypted_dir)
            ) + '.encrypted.decrypted'

            if plaintext_filename.endswith(suffix):
                assert filecmp.cmp(plaintext_filename, decrypted_filename)
            else:
                assert not os.path.isfile(decrypted_filename)
