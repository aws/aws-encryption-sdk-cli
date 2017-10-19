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
"""Unit test suite for ``aws_encryption_sdk_cli.internal.io_handling``."""
import io
import os
import sys

from mock import MagicMock, patch, sentinel
import pytest
from pytest_mock import mocker  # noqa pylint: disable=unused-import
import six

from aws_encryption_sdk_cli.internal import io_handling

DATA = b'aosidhjf9aiwhj3f98wiaj49c8a3hj49f8uwa0edifja9w843hj98'


@pytest.yield_fixture
def patch_makedirs(mocker):
    mocker.patch.object(io_handling.os, 'makedirs')
    yield io_handling.os.makedirs


@pytest.yield_fixture
def patch_aws_encryption_sdk_stream(mocker):
    mocker.patch.object(io_handling.aws_encryption_sdk, 'stream')
    mock_stream = MagicMock()
    io_handling.aws_encryption_sdk.stream.return_value.__enter__.return_value = mock_stream
    mock_stream.__iter__ = MagicMock(return_value=iter((sentinel.chunk_1, sentinel.chunk_2)))
    yield io_handling.aws_encryption_sdk.stream


@pytest.fixture
def patch_for_process_single_operation(mocker):
    mocker.patch.object(io_handling, '_single_io_write')
    mocker.patch.object(io_handling, '_stdout')
    mocker.patch.object(io_handling, '_stdin')
    mocker.patch.object(io_handling, '_ensure_dir_exists')


@pytest.yield_fixture
def patch_input(mocker):
    mocker.patch.object(io_handling.six.moves, 'input')
    yield io_handling.six.moves.input


@pytest.yield_fixture
def patch_process_single_operation(mocker):
    mocker.patch.object(io_handling, 'process_single_operation')
    yield io_handling.process_single_operation


@pytest.yield_fixture
def patch_should_write_file(mocker):
    mocker.patch.object(io_handling, '_should_write_file')
    io_handling._should_write_file.return_value = True
    yield io_handling._should_write_file


def test_stdout():
    if six.PY2:
        assert io_handling._stdout() is sys.stdout
    else:
        assert io_handling._stdout() is sys.stdout.buffer


def test_stdin():
    if six.PY2:
        assert io_handling._stdin() is sys.stdin
    else:
        assert io_handling._stdin() is sys.stdin.buffer


def test_file_exists_error():
    if six.PY3:
        assert io_handling._file_exists_error() is FileExistsError
    else:
        assert io_handling._file_exists_error() is OSError


def test_ensure_dir_exists_already_exists(tmpdir):
    target_dir = tmpdir.mkdir('target')
    io_handling._ensure_dir_exists(str(target_dir))


def test_ensure_dir_exists_shallow_orphan(tmpdir):
    target_parent = tmpdir.mkdir('parent')
    target_dir = os.path.join(str(target_parent), 'target')
    target_file = os.path.join(target_dir, 'file')
    assert not os.path.exists(target_dir)
    io_handling._ensure_dir_exists(target_file)
    assert os.path.isdir(target_dir)


def test_ensure_dir_exists_deep_orphan(tmpdir):
    target_parent = tmpdir.mkdir('parent')
    target_dir = os.path.join(str(target_parent), 'child_1', 'child_2', 'target')
    target_file = os.path.join(target_dir, 'file')
    assert not os.path.exists(target_dir)
    io_handling._ensure_dir_exists(target_file)
    assert os.path.isdir(target_dir)


def test_ensure_dir_exists_current_directory(patch_makedirs):
    io_handling._ensure_dir_exists('filename')
    assert not patch_makedirs.called


def test_single_io_write_stream(tmpdir, patch_aws_encryption_sdk_stream):
    patch_aws_encryption_sdk_stream.return_value = io.BytesIO(DATA)
    target_file = tmpdir.join('target')
    with open(str(target_file), 'wb') as destination_writer:
        io_handling._single_io_write(
            stream_args={
                'a': sentinel.a,
                'b': sentinel.b
            },
            source=sentinel.source,
            destination_writer=destination_writer
        )

    patch_aws_encryption_sdk_stream.assert_called_once_with(
        source=sentinel.source,
        a=sentinel.a,
        b=sentinel.b
    )
    assert target_file.read('rb') == DATA


def test_process_single_operation_stdout(patch_for_process_single_operation, patch_should_write_file):
    io_handling.process_single_operation(
        stream_args=sentinel.stream_args,
        source=sentinel.source,
        destination='-',
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite
    )
    io_handling._single_io_write.assert_called_once_with(
        stream_args=sentinel.stream_args,
        source=sentinel.source,
        destination_writer=io_handling._stdout.return_value
    )
    assert not patch_should_write_file.called
    io_handling._stdout.return_value.close.assert_called_once_with()


def test_process_single_operation_stdin_stdout(patch_for_process_single_operation, patch_should_write_file):
    io_handling.process_single_operation(
        stream_args=sentinel.stream_args,
        source='-',
        destination='-',
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite
    )
    io_handling._single_io_write.assert_called_once_with(
        stream_args=sentinel.stream_args,
        source=io_handling._stdin.return_value,
        destination_writer=io_handling._stdout.return_value
    )


def test_process_single_operation_file(patch_for_process_single_operation, patch_should_write_file):
    with patch('aws_encryption_sdk_cli.internal.io_handling.open', create=True) as mock_open:
        io_handling.process_single_operation(
            stream_args=sentinel.stream_args,
            source=sentinel.source,
            destination=sentinel.destination_file,
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite
        )
    io_handling._ensure_dir_exists.assert_called_once_with(sentinel.destination_file)
    patch_should_write_file.assert_called_once_with(
        filepath=sentinel.destination_file,
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite
    )
    mock_open.assert_called_once_with(sentinel.destination_file, 'wb')
    io_handling._single_io_write.assert_called_once_with(
        stream_args=sentinel.stream_args,
        source=sentinel.source,
        destination_writer=mock_open.return_value
    )
    mock_open.return_value.close.assert_called_once_with()


def test_process_single_operation_file_should_not_write(patch_for_process_single_operation, patch_should_write_file):
    patch_should_write_file.return_value = False
    with patch('aws_encryption_sdk_cli.internal.io_handling.open', create=True) as mock_open:
        io_handling.process_single_operation(
            stream_args=sentinel.stream_args,
            source=sentinel.source,
            destination=sentinel.destination_file,
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite
        )
    assert not io_handling._ensure_dir_exists.called
    assert not mock_open.called
    assert not io_handling._stdout.called


@pytest.mark.parametrize('interactive, no_overwrite', (
    (False, False),
    (False, True),
    (True, False),
    (True, True)
))
def test_f_should_write_file_does_not_exist(tmpdir, interactive, no_overwrite):
    target = tmpdir.join('target')
    assert not os.path.exists(str(target))
    # Should always be true regardless of input if file does not exist
    assert io_handling._should_write_file(
        filepath=str(target),
        interactive=interactive,
        no_overwrite=no_overwrite
    )


@pytest.mark.parametrize('interactive, no_overwrite, user_input, expected', (
    (False, True, None, False),  # no_overwrite is set
    (True, True, None, False),  # both interactive and no_overwrite are set
    (True, False, 'y', True),  # interactive is set, and approval input is provided
    (True, False, 'Y', True),  # interactive is set, and approval input is provided
    (True, False, 'n', False),  # interactive is set, and approval input is not provided
    (True, False, '', False),  # interactive is set, and no input is provided,
    (False, False, None, True)  # interactive is not set, and no_overwrite is not set
))
def test_should_write_file_does_exist(tmpdir, patch_input, interactive, no_overwrite, user_input, expected):
    target_file = tmpdir.join('target')
    target_file.write(b'')
    patch_input.return_value = user_input

    should_write = io_handling._should_write_file(
        filepath=str(target_file),
        interactive=interactive,
        no_overwrite=no_overwrite
    )

    if expected:
        assert should_write
    else:
        assert not should_write


def test_process_single_file(tmpdir, patch_process_single_operation):
    source = tmpdir.join('source')
    source.write('some data')
    destination = tmpdir.join('destination')
    with patch('aws_encryption_sdk_cli.internal.io_handling.open', create=True) as mock_open:
        io_handling.process_single_file(
            stream_args=sentinel.stream_args,
            source=str(source),
            destination=str(destination),
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite
        )
    mock_open.assert_called_once_with(str(source), 'rb')
    patch_process_single_operation.assert_called_once_with(
        stream_args=sentinel.stream_args,
        source=mock_open.return_value.__enter__.return_value,
        destination=str(destination),
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite
    )


def test_process_single_file_source_is_destination(tmpdir, patch_process_single_operation):
    source = tmpdir.join('source')
    source.write('some data')

    with patch('aws_encryption_sdk_cli.internal.io_handling.open', create=True) as mock_open:
        io_handling.process_single_file(
            stream_args=sentinel.stream_args,
            source=str(source),
            destination=str(source),
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite
        )

    assert not mock_open.called
    assert not patch_process_single_operation.called


def test_process_single_file_destination_is_symlink_to_source(tmpdir, patch_process_single_operation):
    source = tmpdir.join('source')
    source.write('some data')
    destination = str(tmpdir.join('destination'))
    os.symlink(str(source), destination)

    with patch('aws_encryption_sdk_cli.internal.io_handling.open', create=True) as mock_open:
        io_handling.process_single_file(
            stream_args=sentinel.stream_args,
            source=str(source),
            destination=destination,
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite
        )

    assert not mock_open.called
    assert not patch_process_single_operation.called


@pytest.mark.parametrize('source, destination, mode, suffix, output', (
    (
        os.path.join('source_dir', 'source_filename'),
        'destination_dir',
        'encrypt',
        None,
        os.path.join('destination_dir', 'source_filename.encrypted')
    ),
    (
        os.path.join('source_dir', 'source_filename.encrypted'),
        'destination_dir',
        'encrypt',
        None,
        os.path.join('destination_dir', 'source_filename.encrypted.encrypted')
    ),
    (
        os.path.join('source_dir', 'source_filename'),
        'destination_dir',
        'decrypt',
        None,
        os.path.join('destination_dir', 'source_filename.decrypted')
    ),
    (
        os.path.join('source_dir', 'source_filename.encrypted'),
        'destination_dir',
        'decrypt',
        None,
        os.path.join('destination_dir', 'source_filename.encrypted.decrypted')
    ),
    (
        os.path.join('source_dir', 'source_filename'),
        'destination_dir',
        'encrypt',
        'CUSTOM_SUFFIX',
        os.path.join('destination_dir', 'source_filenameCUSTOM_SUFFIX')
    ),
    (
        os.path.join('source_dir', 'source_filename'),
        'destination_dir',
        'decrypt',
        'CUSTOM_SUFFIX',
        os.path.join('destination_dir', 'source_filenameCUSTOM_SUFFIX')
    )
))
def test_output_filename(source, destination, mode, suffix, output):
    assert io_handling.output_filename(source, destination, mode, suffix) == output


@pytest.mark.parametrize('source_root, destination_root, source_dir, output', (
    (
        'source_dir',
        'destination_dir',
        os.path.join('source_dir', 'child_1'),
        os.path.join('destination_dir', 'child_1')
    ),
    (
        'source_dir',
        'destination_dir',
        os.path.join('source_dir', 'child_1', 'child_2', 'child_3'),
        os.path.join('destination_dir', 'child_1', 'child_2', 'child_3')
    ),
    (
        os.path.join('source_dir', 'actual_source_root'),
        'destination_dir',
        os.path.join('source_dir', 'actual_source_root', 'child_1'),
        os.path.join('destination_dir', 'child_1')
    )
))
def test_output_dir(source_root, destination_root, source_dir, output):
    assert io_handling._output_dir(source_root, destination_root, source_dir) == output


def _mock_aws_encryption_sdk_stream_output(source, *args, **kwargs):
    source_filename = source.name
    suffix = source_filename.rsplit('_', 1)[-1]
    return io.BytesIO(DATA + six.b(suffix))


def test_process_dir(tmpdir, patch_aws_encryption_sdk_stream):
    patch_aws_encryption_sdk_stream.side_effect = _mock_aws_encryption_sdk_stream_output
    source = tmpdir.mkdir('source')
    source.mkdir('a')
    source.join('a', 'target_a1').write(b'')
    source.join('a', 'target_a2').write(b'')
    b_dir = source.mkdir('b')
    source.join('b', 'target_b1').write(b'')
    source.join('b', 'target_b2').write(b'')
    c_dir = b_dir.mkdir('c')
    b_dir.join('c', 'target_c1').write(b'')
    b_dir.join('c', 'target_c2').write(b'')
    e_dir = c_dir.mkdir('d').mkdir('e')
    e_dir.join('target_e1').write(b'')
    target = tmpdir.mkdir('target')

    io_handling.process_dir(
        stream_args={'mode': 'encrypt'},
        source=str(source),
        destination=str(target),
        interactive=False,
        no_overwrite=False,
        suffix=None
    )

    for filename, suffix in (
            (os.path.join(str(target), 'a', 'target_a1.encrypted'), b'a1'),
            (os.path.join(str(target), 'a', 'target_a2.encrypted'), b'a2'),
            (os.path.join(str(target), 'b', 'target_b1.encrypted'), b'b1'),
            (os.path.join(str(target), 'b', 'target_b2.encrypted'), b'b2'),
            (os.path.join(str(target), 'b', 'c', 'target_c1.encrypted'), b'c1'),
            (os.path.join(str(target), 'b', 'c', 'target_c2.encrypted'), b'c2'),
            (os.path.join(str(target), 'b', 'c', 'd', 'e', 'target_e1.encrypted'), b'e1')
    ):
        assert os.path.isfile(filename)
        with open(filename, 'rb') as f:
            assert f.read() == DATA + suffix
