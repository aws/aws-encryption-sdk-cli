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
"""Unit test suite for ``aws_encryption_sdk_cli``."""
import os

import aws_encryption_sdk
from mock import MagicMock, sentinel
import pytest

import aws_encryption_sdk_cli
from aws_encryption_sdk_cli.exceptions import BadUserArgumentError


def patch_reactive_side_effect(kwargs):
    def _check(path):
        return kwargs[path]
    return _check


@pytest.yield_fixture
def patch_process_dir(mocker):
    mocker.patch.object(aws_encryption_sdk_cli, 'process_dir')
    yield aws_encryption_sdk_cli.process_dir


@pytest.yield_fixture
def patch_process_single_file(mocker):
    mocker.patch.object(aws_encryption_sdk_cli, 'process_single_file')
    yield aws_encryption_sdk_cli.process_single_file


@pytest.fixture
def patch_for_process_cli_request(mocker, patch_process_dir, patch_process_single_file):
    mocker.patch.object(aws_encryption_sdk_cli.os.path, 'isdir')
    mocker.patch.object(aws_encryption_sdk_cli.os.path, 'isfile')
    mocker.patch.object(aws_encryption_sdk_cli, 'output_filename')
    aws_encryption_sdk_cli.output_filename.return_value = sentinel.destination_filename
    mocker.patch.object(aws_encryption_sdk_cli, 'process_single_operation')
    mocker.patch.object(aws_encryption_sdk_cli.glob, 'glob')
    aws_encryption_sdk_cli.glob.glob.side_effect = lambda x: [x]


def test_process_cli_request_source_is_destination(patch_for_process_cli_request):
    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli.process_cli_request(
            stream_args=sentinel.stream_args,
            source=sentinel.source,
            destination=sentinel.source,
            recursive=True,
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite
        )
    excinfo.match(r'Destination and source cannot be the same')


def test_process_cli_request_source_dir_nonrecursive(patch_for_process_cli_request):
    aws_encryption_sdk_cli.os.path.isdir.side_effect = patch_reactive_side_effect({
        sentinel.source: True,
        sentinel.destination: True
    })
    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli.process_cli_request(
            stream_args=sentinel.stream_args,
            source=sentinel.source,
            destination=sentinel.destination,
            recursive=False,
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite
        )
    excinfo.match(r'Must specify -r/-R/--recursive when operating on a source directory')


def test_process_cli_request_source_dir_destination_nondir(patch_for_process_cli_request):
    aws_encryption_sdk_cli.os.path.isdir.side_effect = patch_reactive_side_effect({
        sentinel.source: True,
        sentinel.destination: False
    })
    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli.process_cli_request(
            stream_args=sentinel.stream_args,
            source=sentinel.source,
            destination=sentinel.destination,
            recursive=True,
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite
        )
    excinfo.match(r'If operating on a source directory, destination must be an existing directory')


def test_process_cli_request_source_dir_destination_dir(patch_for_process_cli_request):
    aws_encryption_sdk_cli.os.path.isdir.side_effect = patch_reactive_side_effect({
        sentinel.source: True,
        'a specific destination': True
    })
    aws_encryption_sdk_cli.os.path.isfile.side_effect = patch_reactive_side_effect({
        sentinel.source: False
    })
    aws_encryption_sdk_cli.process_cli_request(
        stream_args=sentinel.stream_args,
        source=sentinel.source,
        destination='a specific destination',
        recursive=True,
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite,
        suffix=sentinel.suffix
    )
    aws_encryption_sdk_cli.process_dir.assert_called_once_with(
        stream_args=sentinel.stream_args,
        source=sentinel.source,
        destination='a specific destination',
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite,
        suffix=sentinel.suffix
    )
    assert not aws_encryption_sdk_cli.os.path.isfile.called
    assert not aws_encryption_sdk_cli.output_filename.called
    assert not aws_encryption_sdk_cli.process_single_file.called
    assert not aws_encryption_sdk_cli.process_single_operation.called


def test_process_cli_request_source_stdin_destination_dir(patch_for_process_cli_request):
    aws_encryption_sdk_cli.os.path.isdir.side_effect = patch_reactive_side_effect({
        '-': False,
        sentinel.destination: True
    })
    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli.process_cli_request(
            stream_args=sentinel.stream_args,
            source='-',
            destination=sentinel.destination,
            recursive=False,
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite
        )
    excinfo.match(r'Destination may not be a directory when source is stdin')


def test_process_cli_request_source_stdin(patch_for_process_cli_request):
    aws_encryption_sdk_cli.os.path.isdir.side_effect = patch_reactive_side_effect({
        '-': False,
        sentinel.destination: False
    })
    aws_encryption_sdk_cli.process_cli_request(
        stream_args=sentinel.stream_args,
        source='-',
        destination=sentinel.destination,
        recursive=False,
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite
    )
    assert not aws_encryption_sdk_cli.process_dir.called
    assert not aws_encryption_sdk_cli.os.path.isfile.called
    assert not aws_encryption_sdk_cli.output_filename.called
    assert not aws_encryption_sdk_cli.process_single_file.called
    aws_encryption_sdk_cli.process_single_operation.assert_called_once_with(
        stream_args=sentinel.stream_args,
        source='-',
        destination=sentinel.destination,
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite
    )


def test_process_cli_request_source_file_destination_dir(patch_for_process_cli_request):
    aws_encryption_sdk_cli.os.path.isdir.side_effect = patch_reactive_side_effect({
        sentinel.source: False,
        'a specific destination': True
    })
    aws_encryption_sdk_cli.os.path.isfile.side_effect = patch_reactive_side_effect({
        sentinel.source: True
    })
    aws_encryption_sdk_cli.process_cli_request(
        stream_args={'mode': sentinel.mode},
        source=sentinel.source,
        destination='a specific destination',
        recursive=False,
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite,
        suffix=sentinel.suffix
    )
    assert not aws_encryption_sdk_cli.process_dir.called
    assert not aws_encryption_sdk_cli.process_single_operation.called
    aws_encryption_sdk_cli.os.path.isfile.assert_called_once_with(sentinel.source)
    aws_encryption_sdk_cli.output_filename.assert_called_once_with(
        source_filename=sentinel.source,
        destination_dir='a specific destination',
        mode=str(sentinel.mode),
        suffix=sentinel.suffix
    )
    aws_encryption_sdk_cli.process_single_file.assert_called_once_with(
        stream_args={'mode': sentinel.mode},
        source=sentinel.source,
        destination=sentinel.destination_filename,
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite
    )


def test_process_cli_request_source_file_destination_file(patch_for_process_cli_request):
    aws_encryption_sdk_cli.os.path.isdir.side_effect = patch_reactive_side_effect({
        sentinel.source: False,
        'a specific destination': False
    })
    aws_encryption_sdk_cli.os.path.isfile.side_effect = patch_reactive_side_effect({
        sentinel.source: True
    })
    aws_encryption_sdk_cli.process_cli_request(
        stream_args={'mode': sentinel.mode},
        source=sentinel.source,
        destination='a specific destination',
        recursive=False,
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite
    )
    assert not aws_encryption_sdk_cli.process_dir.called
    assert not aws_encryption_sdk_cli.process_single_operation.called
    aws_encryption_sdk_cli.os.path.isfile.assert_called_once_with(sentinel.source)
    assert not aws_encryption_sdk_cli.output_filename.called
    aws_encryption_sdk_cli.process_single_file.assert_called_once_with(
        stream_args={'mode': sentinel.mode},
        source=sentinel.source,
        destination='a specific destination',
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite
    )


def test_process_cli_request_invalid_source(tmpdir):
    target = os.path.join(str(tmpdir), 'test_targets.*')
    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli.process_cli_request(
            stream_args={},
            source=target,
            destination='a specific destination',
            recursive=False,
            interactive=False,
            no_overwrite=False
        )
    excinfo.match(r'Invalid source.  Must be a valid pathname pattern or stdin \(-\)')


def test_process_cli_request_globbed_source_non_directory_target(tmpdir, patch_process_dir, patch_process_single_file):
    plaintext_dir = tmpdir.mkdir('plaintext')
    test_file = plaintext_dir.join('testing.aa')
    test_file.write(b'some data here!')
    test_file = plaintext_dir.join('testing.bb')
    test_file.write(b'some data here!')
    ciphertext_dir = tmpdir.mkdir('ciphertext')
    target_file = ciphertext_dir.join('target_file')
    source = os.path.join(str(plaintext_dir), 'testing.*')

    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli.process_cli_request(
            stream_args={'mode': 'encrypt'},
            source=source,
            destination=str(target_file),
            recursive=False,
            interactive=False,
            no_overwrite=False
        )

    excinfo.match('If operating on multiple sources, destination must be an existing directory')
    assert not patch_process_dir.called
    assert not patch_process_single_file.called


def test_process_cli_request_source_contains_directory_nonrecursive(
        tmpdir,
        patch_process_dir,
        patch_process_single_file
):
    plaintext_dir = tmpdir.mkdir('plaintext')
    test_file = plaintext_dir.join('testing.aa')
    test_file.write(b'some data here!')
    plaintext_dir.mkdir('testing.bb')
    ciphertext_dir = tmpdir.mkdir('ciphertext')
    source = os.path.join(str(plaintext_dir), 'testing.*')

    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli.process_cli_request(
            stream_args={'mode': 'encrypt'},
            source=source,
            destination=str(ciphertext_dir),
            recursive=False,
            interactive=False,
            no_overwrite=False
        )

    excinfo.match('Must specify -r/-R/--recursive when operating on a source directory')
    assert not patch_process_dir.called
    assert not patch_process_single_file.called


@pytest.mark.parametrize('args, stream_args', (
    (
        MagicMock(
            action=sentinel.mode,
            encryption_context=None,
            algorithm=None,
            frame_length=None,
            max_length=None
        ),
        {
            'materials_manager': sentinel.materials_manager,
            'mode': sentinel.mode
        }
    ),
    (
        MagicMock(
            action=sentinel.mode,
            encryption_context=None,
            algorithm=None,
            frame_length=None,
            max_length=sentinel.max_length
        ),
        {
            'materials_manager': sentinel.materials_manager,
            'mode': sentinel.mode,
            'max_body_length': sentinel.max_length
        }
    ),
    (
        MagicMock(
            action=sentinel.mode,
            encryption_context=None,
            algorithm=None,
            frame_length=None,
            max_length=None
        ),
        {
            'materials_manager': sentinel.materials_manager,
            'mode': sentinel.mode,
        }
    ),
    (
        MagicMock(
            action=sentinel.mode,
            encryption_context=sentinel.encryption_context,
            algorithm='AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384',
            frame_length=sentinel.frame_length,
            max_length=None
        ),
        {
            'materials_manager': sentinel.materials_manager,
            'mode': sentinel.mode,
        }
    ),
    (
        MagicMock(
            action='encrypt',
            encryption_context=sentinel.encryption_context,
            algorithm='AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384',
            frame_length=sentinel.frame_length,
            max_length=None
        ),
        {
            'materials_manager': sentinel.materials_manager,
            'mode': 'encrypt',
            'encryption_context': sentinel.encryption_context,
            'algorithm': aws_encryption_sdk.Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
            'frame_length': sentinel.frame_length,
        }
    ),
    (
        MagicMock(
            action='encrypt',
            encryption_context=None,
            algorithm='AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384',
            frame_length=sentinel.frame_length,
            max_length=None
        ),
        {
            'materials_manager': sentinel.materials_manager,
            'mode': 'encrypt',
            'algorithm': aws_encryption_sdk.Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
            'frame_length': sentinel.frame_length,
        }
    ),
    (
        MagicMock(
            action='encrypt',
            encryption_context=sentinel.encryption_context,
            algorithm=None,
            frame_length=sentinel.frame_length,
            max_length=None
        ),
        {
            'materials_manager': sentinel.materials_manager,
            'mode': 'encrypt',
            'encryption_context': sentinel.encryption_context,
            'frame_length': sentinel.frame_length
        }
    ),
    (
        MagicMock(
            action='encrypt',
            encryption_context=sentinel.encryption_context,
            algorithm='AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384',
            frame_length=None,
            max_length=None
        ),
        {
            'materials_manager': sentinel.materials_manager,
            'mode': 'encrypt',
            'encryption_context': sentinel.encryption_context,
            'algorithm': aws_encryption_sdk.Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
        }
    )
))
def test_stream_kwargs_from_args(args, stream_args):
    assert aws_encryption_sdk_cli.stream_kwargs_from_args(args, sentinel.materials_manager) == stream_args


@pytest.fixture
def patch_for_cli(mocker):
    mocker.patch.object(aws_encryption_sdk_cli, 'parse_args')
    aws_encryption_sdk_cli.parse_args.return_value = MagicMock(
        version=False,
        verbosity=sentinel.verbosity,
        quiet=sentinel.quiet,
        master_keys=sentinel.master_keys,
        caching=sentinel.caching_config,
        input=sentinel.input,
        output=sentinel.output,
        recursive=sentinel.recursive,
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite,
        suffix=sentinel.suffix
    )
    mocker.patch.object(aws_encryption_sdk_cli, 'setup_logger')
    mocker.patch.object(aws_encryption_sdk_cli, 'build_crypto_materials_manager_from_args')
    aws_encryption_sdk_cli.build_crypto_materials_manager_from_args.return_value = sentinel.crypto_materials_manager
    mocker.patch.object(aws_encryption_sdk_cli, 'stream_kwargs_from_args')
    aws_encryption_sdk_cli.stream_kwargs_from_args.return_value = sentinel.stream_args
    mocker.patch.object(aws_encryption_sdk_cli, 'process_cli_request')


def test_cli(patch_for_cli):
    test = aws_encryption_sdk_cli.cli(sentinel.raw_args)

    aws_encryption_sdk_cli.parse_args.assert_called_once_with(sentinel.raw_args)
    aws_encryption_sdk_cli.setup_logger.assert_called_once_with(
        sentinel.verbosity,
        sentinel.quiet
    )
    aws_encryption_sdk_cli.build_crypto_materials_manager_from_args.assert_called_once_with(
        key_providers_config=sentinel.master_keys,
        caching_config=sentinel.caching_config
    )
    aws_encryption_sdk_cli.stream_kwargs_from_args.assert_called_once_with(
        aws_encryption_sdk_cli.parse_args.return_value,
        sentinel.crypto_materials_manager
    )
    aws_encryption_sdk_cli.process_cli_request.assert_called_once_with(
        stream_args=sentinel.stream_args,
        source=sentinel.input,
        destination=sentinel.output,
        recursive=sentinel.recursive,
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite,
        suffix=sentinel.suffix
    )
    assert test is None


def test_cli_bad_user_input(patch_for_cli):
    aws_encryption_sdk_cli.process_cli_request.side_effect = BadUserArgumentError(sentinel.error_message)
    test = aws_encryption_sdk_cli.cli()

    assert test is sentinel.error_message
