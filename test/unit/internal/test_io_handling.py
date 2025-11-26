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
import base64
import io
import os
import sys

import pytest
import six
from aws_encryption_sdk.materials_managers import CommitmentPolicy
from mock import MagicMock, call, patch, sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

from aws_encryption_sdk_cli import BadUserArgumentError
from aws_encryption_sdk_cli.internal import identifiers, io_handling, metadata

from ..unit_test_utils import WINDOWS_SKIP_MESSAGE, is_windows

pytestmark = [pytest.mark.unit, pytest.mark.local]
DATA = b"aosidhjf9aiwhj3f98wiaj49c8a3hj49f8uwa0edifja9w843hj98"


@pytest.fixture
def patch_makedirs(mocker):
    mocker.patch.object(io_handling.os, "makedirs")
    yield io_handling.os.makedirs


@pytest.fixture
def patch_aws_encryption_sdk_stream(mocker):
    mocker.patch.object(io_handling.aws_encryption_sdk.EncryptionSDKClient, "stream")
    mock_stream = MagicMock()
    io_handling.aws_encryption_sdk.EncryptionSDKClient.stream.return_value.__enter__.return_value = mock_stream
    mock_stream.__iter__ = MagicMock(return_value=iter((sentinel.chunk_1, sentinel.chunk_2)))
    yield io_handling.aws_encryption_sdk.EncryptionSDKClient.stream


@pytest.fixture
def patch_os_remove(mocker):
    mocker.patch.object(io_handling.os, "remove")
    return io_handling.os.remove


@pytest.fixture
def patch_single_io_write(mocker):
    mocker.patch.object(io_handling.IOHandler, "_single_io_write")
    return io_handling.IOHandler._single_io_write


@pytest.fixture
def patch_for_process_single_operation(mocker, patch_single_io_write):
    mocker.patch.object(io_handling, "_stdout")
    mocker.patch.object(io_handling, "_stdin")
    mocker.patch.object(io_handling, "_ensure_dir_exists")


@pytest.fixture
def patch_input(mocker):
    mocker.patch.object(io_handling.six.moves, "input")
    yield io_handling.six.moves.input


@pytest.fixture
def patch_process_single_operation(mocker):
    mocker.patch.object(io_handling.IOHandler, "process_single_operation")
    yield io_handling.IOHandler.process_single_operation


@pytest.fixture
def patch_should_write_file(mocker):
    mocker.patch.object(io_handling.IOHandler, "_should_write_file")
    io_handling.IOHandler._should_write_file.return_value = True
    yield io_handling.IOHandler._should_write_file


@pytest.fixture
def patch_json_ready_header(mocker):
    mocker.patch.object(io_handling, "json_ready_header")
    return io_handling.json_ready_header


@pytest.fixture
def patch_json_ready_header_auth(mocker):
    mocker.patch.object(io_handling, "json_ready_header_auth")
    return io_handling.json_ready_header_auth


GOOD_IOHANDLER_KWARGS = dict(
    metadata_writer=metadata.MetadataWriter(True)(),
    interactive=False,
    no_overwrite=False,
    decode_input=False,
    encode_output=False,
    required_encryption_context={},
    required_encryption_context_keys=[],
    commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
    buffer_output=False,
    max_encrypted_data_keys=None,
)


@pytest.fixture
def standard_handler():
    return io_handling.IOHandler(**GOOD_IOHANDLER_KWARGS)


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
    target_dir = tmpdir.mkdir("target")
    io_handling._ensure_dir_exists(str(target_dir))


def test_ensure_dir_exists_shallow_orphan(tmpdir):
    target_parent = tmpdir.mkdir("parent")
    target_dir = os.path.join(str(target_parent), "target")
    target_file = os.path.join(target_dir, "file")
    assert not os.path.exists(target_dir)
    io_handling._ensure_dir_exists(target_file)
    assert os.path.isdir(target_dir)


def test_ensure_dir_exists_deep_orphan(tmpdir):
    target_parent = tmpdir.mkdir("parent")
    target_dir = os.path.join(str(target_parent), "child_1", "child_2", "target")
    target_file = os.path.join(target_dir, "file")
    assert not os.path.exists(target_dir)
    io_handling._ensure_dir_exists(target_file)
    assert os.path.isdir(target_dir)


def test_ensure_dir_exists_current_directory(patch_makedirs):
    io_handling._ensure_dir_exists("filename")
    assert not patch_makedirs.called


@pytest.mark.parametrize("should_base64", (True, False))
def test_encoder(mocker, should_base64):
    mocker.patch.object(io_handling, "Base64IO")

    test = io_handling._encoder(sentinel.stream, should_base64)

    if should_base64:
        assert test is io_handling.Base64IO.return_value
    else:
        assert test is sentinel.stream


@pytest.mark.parametrize("mode, expected", (("decrypt", True), ("decrypt-unsigned", True), ("encrypt", False)))
def test_is_decrypt_mode(mode, expected):
    assert io_handling._is_decrypt_mode(mode) == expected


@pytest.mark.parametrize("invalid_mode", ("not-a-mode", "dedecrypt", "decrypt-signed", "encrypt-unsigned", "crypt"))
def test_is_decrypt_mode_exception(invalid_mode):
    with pytest.raises(BadUserArgumentError) as excinfo:
        io_handling._is_decrypt_mode(invalid_mode)

    excinfo.match(r"Mode {mode} has not been implemented".format(mode=invalid_mode))


def test_iohandler_attrs_good():
    io_handling.IOHandler(**GOOD_IOHANDLER_KWARGS)


@pytest.mark.parametrize(
    "kwargs",
    (
        dict(metadata_writer="not a MetadataWriter"),
        dict(interactive="not a bool"),
        dict(no_overwrite="not a bool"),
        dict(decode_input="not a bool"),
        dict(encode_output="not a bool"),
        dict(encryption_context="not a dict"),
        dict(required_encryption_context_keys="not a list"),
        dict(commitment_policy="not a CommitmentPolicy"),
        dict(buffer_output="not a bool"),
    ),
)
def test_iohandler_attrs_fail(kwargs):
    _kwargs = GOOD_IOHANDLER_KWARGS.copy()
    _kwargs.update(kwargs)

    with pytest.raises(TypeError):
        io_handling.IOHandler(**_kwargs)


def test_single_io_write_stream_encrypt(
    tmpdir, patch_aws_encryption_sdk_stream, patch_json_ready_header, patch_json_ready_header_auth, standard_handler
):
    patch_aws_encryption_sdk_stream.return_value = io.BytesIO(DATA)
    patch_aws_encryption_sdk_stream.return_value.header = MagicMock()
    target_file = tmpdir.join("target")
    mock_source = MagicMock()
    standard_handler.metadata_writer = MagicMock()
    with open(str(target_file), "wb") as destination_writer:
        standard_handler._single_io_write(
            stream_args={"mode": "encrypt", "a": sentinel.a, "b": sentinel.b},
            source=mock_source,
            destination_writer=destination_writer,
        )

    patch_aws_encryption_sdk_stream.assert_called_once_with(
        mode="encrypt", source=mock_source.__enter__.return_value, a=sentinel.a, b=sentinel.b
    )
    patch_json_ready_header.assert_called_once_with(patch_aws_encryption_sdk_stream.return_value.header)
    assert not patch_json_ready_header_auth.called
    standard_handler.metadata_writer.__enter__.return_value.write_metadata.assert_called_once_with(
        mode="encrypt",
        input=mock_source.name,
        output=destination_writer.name,
        header=patch_json_ready_header.return_value,
    )
    assert target_file.read("rb") == DATA


def test_single_io_write_stream_decrypt(
    tmpdir, patch_aws_encryption_sdk_stream, patch_json_ready_header, patch_json_ready_header_auth, standard_handler
):
    patch_aws_encryption_sdk_stream.return_value = io.BytesIO(DATA)
    patch_aws_encryption_sdk_stream.return_value.header = MagicMock()
    patch_aws_encryption_sdk_stream.return_value.header_auth = MagicMock()
    target_file = tmpdir.join("target")
    mock_source = MagicMock()
    standard_handler.metadata_writer = MagicMock()
    with open(str(target_file), "wb") as destination_writer:
        standard_handler._single_io_write(
            stream_args={"mode": "decrypt", "a": sentinel.a, "b": sentinel.b},
            source=mock_source,
            destination_writer=destination_writer,
        )
    patch_json_ready_header_auth.assert_called_once_with(patch_aws_encryption_sdk_stream.return_value.header_auth)
    standard_handler.metadata_writer.__enter__.return_value.write_metadata.assert_called_once_with(
        mode="decrypt",
        input=mock_source.name,
        output=destination_writer.name,
        header=patch_json_ready_header.return_value,
        header_auth=patch_json_ready_header_auth.return_value,
    )


def test_single_io_write_stream_decrypt_unsigned(
    tmpdir, patch_aws_encryption_sdk_stream, patch_json_ready_header, patch_json_ready_header_auth, standard_handler
):
    patch_aws_encryption_sdk_stream.return_value = io.BytesIO(DATA)
    patch_aws_encryption_sdk_stream.return_value.header = MagicMock()
    patch_aws_encryption_sdk_stream.return_value.header_auth = MagicMock()
    target_file = tmpdir.join("target")
    mock_source = MagicMock()
    standard_handler.metadata_writer = MagicMock()
    with open(str(target_file), "wb") as destination_writer:
        standard_handler._single_io_write(
            stream_args={"mode": "decrypt-unsigned", "a": sentinel.a, "b": sentinel.b},
            source=mock_source,
            destination_writer=destination_writer,
        )
    patch_json_ready_header_auth.assert_called_once_with(patch_aws_encryption_sdk_stream.return_value.header_auth)
    standard_handler.metadata_writer.__enter__.return_value.write_metadata.assert_called_once_with(
        mode="decrypt-unsigned",
        input=mock_source.name,
        output=destination_writer.name,
        header=patch_json_ready_header.return_value,
        header_auth=patch_json_ready_header_auth.return_value,
    )


def test_single_io_write_stream_encode_output(
    tmpdir, patch_aws_encryption_sdk_stream, patch_json_ready_header, patch_json_ready_header_auth
):
    patch_aws_encryption_sdk_stream.return_value = io.BytesIO(DATA)
    patch_aws_encryption_sdk_stream.return_value.header = MagicMock(encryption_context=sentinel.encryption_context)
    target_file = tmpdir.join("target")
    mock_source = MagicMock()
    kwargs = GOOD_IOHANDLER_KWARGS.copy()
    kwargs["encode_output"] = True
    handler = io_handling.IOHandler(**kwargs)
    with open(str(target_file), "wb") as destination_writer:
        handler._single_io_write(
            stream_args={"mode": "encrypt", "a": sentinel.a, "b": sentinel.b},
            source=mock_source,
            destination_writer=destination_writer,
        )

    assert target_file.read("rb") == base64.b64encode(DATA)


def test_single_io_write_stream_buffer_output(
    tmpdir, patch_aws_encryption_sdk_stream, patch_json_ready_header, patch_json_ready_header_auth
):
    mock_source = MagicMock()
    mock_destination = MagicMock()
    kwargs = GOOD_IOHANDLER_KWARGS.copy()
    kwargs["buffer_output"] = True
    handler = io_handling.IOHandler(**kwargs)

    handler._single_io_write(
        stream_args={"mode": "encrypt", "a": sentinel.a, "b": sentinel.b},
        source=mock_source,
        destination_writer=mock_destination,
    )

    patch_aws_encryption_sdk_stream.return_value.__enter__.return_value.read.assert_called_once()
    mock_destination.__enter__.return_value.write.assert_called_once()


def test_single_io_write_stream_no_buffering(
    tmpdir, patch_aws_encryption_sdk_stream, patch_json_ready_header, patch_json_ready_header_auth
):
    patch_aws_encryption_sdk_stream.return_value.__enter__.return_value.__iter__ = MagicMock(
        return_value=iter((sentinel.chunk_1, sentinel.chunk_2))
    )

    mock_source = MagicMock()
    mock_destination = MagicMock()
    kwargs = GOOD_IOHANDLER_KWARGS.copy()
    kwargs["buffer_output"] = False
    handler = io_handling.IOHandler(**kwargs)

    handler._single_io_write(
        stream_args={"mode": "encrypt", "a": sentinel.a, "b": sentinel.b},
        source=mock_source,
        destination_writer=mock_destination,
    )

    patch_aws_encryption_sdk_stream.return_value.__enter__.return_value.__iter__.assert_called_once()
    mock_destination.__enter__.return_value.write.assert_has_calls([call(sentinel.chunk_1), call(sentinel.chunk_2)])


def test_process_single_operation_stdout(patch_for_process_single_operation, patch_should_write_file, standard_handler):
    standard_handler.process_single_operation(stream_args=sentinel.stream_args, source=sentinel.source, destination="-")
    io_handling.IOHandler._single_io_write.assert_called_once_with(
        stream_args=sentinel.stream_args, source=sentinel.source, destination_writer=io_handling._stdout.return_value
    )
    assert not patch_should_write_file.called


def test_process_single_operation_stdin_stdout(
    patch_for_process_single_operation, patch_should_write_file, standard_handler
):
    standard_handler.process_single_operation(stream_args=sentinel.stream_args, source="-", destination="-")
    io_handling.IOHandler._single_io_write.assert_called_once_with(
        stream_args=sentinel.stream_args,
        source=io_handling._stdin.return_value,
        destination_writer=io_handling._stdout.return_value,
    )


def test_process_single_operation_file(
    tmpdir, patch_for_process_single_operation, patch_should_write_file, standard_handler
):
    destination = tmpdir.join("destination")
    with tmpdir.as_cwd():
        with patch("aws_encryption_sdk_cli.internal.io_handling.open", create=True) as mock_open:
            standard_handler.process_single_operation(
                stream_args=sentinel.stream_args, source=sentinel.source, destination="destination"
            )
    io_handling._ensure_dir_exists.assert_called_once_with("destination")
    patch_should_write_file.assert_called_once_with("destination")
    mock_open.assert_called_once_with(str(destination), "wb")
    io_handling.IOHandler._single_io_write.assert_called_once_with(
        stream_args=sentinel.stream_args, source=sentinel.source, destination_writer=mock_open.return_value
    )


def test_process_single_operation_file_should_not_write(
    patch_for_process_single_operation, patch_should_write_file, standard_handler
):
    patch_should_write_file.return_value = False
    with patch("aws_encryption_sdk_cli.internal.io_handling.open", create=True) as mock_open:
        standard_handler.process_single_operation(
            stream_args=sentinel.stream_args, source=sentinel.source, destination=sentinel.destination_file
        )
    assert not io_handling._ensure_dir_exists.called
    assert not mock_open.called
    assert not io_handling._stdout.called


@pytest.mark.functional
@pytest.mark.parametrize("interactive, no_overwrite", ((False, False), (False, True), (True, False), (True, True)))
def test_f_should_write_file_does_not_exist(tmpdir, interactive, no_overwrite):
    target = tmpdir.join("target")
    assert not os.path.exists(str(target))
    # Should always be true regardless of input if file does not exist
    kwargs = GOOD_IOHANDLER_KWARGS.copy()
    kwargs.update(dict(interactive=interactive, no_overwrite=no_overwrite))
    handler = io_handling.IOHandler(**kwargs)

    assert handler._should_write_file(str(target))


@pytest.mark.parametrize(
    "interactive, no_overwrite, user_input, expected",
    (
        (False, True, None, False),  # no_overwrite is set
        (True, True, None, False),  # both interactive and no_overwrite are set
        (True, False, "y", True),  # interactive is set, and approval input is provided
        (True, False, "Y", True),  # interactive is set, and approval input is provided
        (True, False, "n", False),  # interactive is set, and approval input is not provided
        (True, False, "", False),  # interactive is set, and no input is provided,
        (False, False, None, True),  # interactive is not set, and no_overwrite is not set
    ),
)
def test_should_write_file_does_exist(tmpdir, patch_input, interactive, no_overwrite, user_input, expected):
    target_file = tmpdir.join("target")
    target_file.write(b"")
    patch_input.return_value = user_input
    kwargs = GOOD_IOHANDLER_KWARGS.copy()
    kwargs.update(dict(interactive=interactive, no_overwrite=no_overwrite))
    handler = io_handling.IOHandler(**kwargs)

    should_write = handler._should_write_file(str(target_file))

    if expected:
        assert should_write
    else:
        assert not should_write


@pytest.mark.parametrize(
    "mode, decode_input, encode_output, expected_multiplier",
    (
        ("encrypt", False, False, 1.0),
        ("encrypt", True, False, 0.75),
        ("encrypt", False, True, 1.0),
        ("encrypt", True, True, 1.0),
        ("decrypt", False, False, 1.0),
        ("decrypt", True, False, 0.75),
        ("decrypt", False, True, 1.0),
        ("decrypt", True, True, 1.0),
        ("decrypt-unsigned", False, False, 1.0),
        ("decrypt-unsigned", True, False, 0.75),
        ("decrypt-unsigned", False, True, 1.0),
        ("decrypt-unsigned", True, True, 1.0),
    ),
)
def test_process_single_file(
    tmpdir, patch_process_single_operation, mode, decode_input, encode_output, expected_multiplier
):
    patch_process_single_operation.return_value = identifiers.OperationResult.SUCCESS
    source = tmpdir.join("source")
    source.write("some data")
    kwargs = GOOD_IOHANDLER_KWARGS.copy()
    kwargs.update(dict(decode_input=decode_input, encode_output=encode_output))
    handler = io_handling.IOHandler(**kwargs)
    destination = tmpdir.join("destination")
    initial_kwargs = dict(mode=mode, a=sentinel.a, b=sentinel.b)
    expected_length = int(os.path.getsize(str(source)) * expected_multiplier)
    updated_kwargs = dict(mode=mode, a=sentinel.a, b=sentinel.b, source_length=expected_length)
    with patch("aws_encryption_sdk_cli.internal.io_handling.open", create=True) as mock_open:
        handler.process_single_file(stream_args=initial_kwargs, source=str(source), destination=str(destination))
    mock_open.assert_called_once_with(str(source), "rb")
    patch_process_single_operation.assert_called_once_with(
        stream_args=updated_kwargs, source=mock_open.return_value.__enter__.return_value, destination=str(destination)
    )


def test_process_single_file_unknown_error(tmpdir, patch_single_io_write, standard_handler):
    patch_single_io_write.side_effect = Exception("This is an unknown exception!")
    source = tmpdir.join("source")
    source.write("some data")
    destination = tmpdir.join("destination")

    with pytest.raises(Exception) as excinfo:
        standard_handler.process_single_file(
            stream_args={"mode": "encrypt"}, source=str(source), destination=str(destination)
        )

    excinfo.match(r"This is an unknown exception!")
    assert not destination.isfile()


def test_process_single_file_source_is_destination(tmpdir, patch_process_single_operation, standard_handler):
    source = tmpdir.join("source")
    source.write("some data")

    with patch("aws_encryption_sdk_cli.internal.io_handling.open", create=True) as mock_open:
        standard_handler.process_single_file(
            stream_args=sentinel.stream_args, source=str(source), destination=str(source)
        )

    assert not mock_open.called
    assert not patch_process_single_operation.called


@pytest.mark.skipif(is_windows(), reason=WINDOWS_SKIP_MESSAGE)
def test_process_single_file_destination_is_symlink_to_source(tmpdir, patch_process_single_operation, standard_handler):
    source = tmpdir.join("source")
    source.write("some data")
    destination = str(tmpdir.join("destination"))
    os.symlink(str(source), destination)

    with patch("aws_encryption_sdk_cli.internal.io_handling.open", create=True) as mock_open:
        standard_handler.process_single_file(
            stream_args=sentinel.stream_args, source=str(source), destination=destination
        )

    assert not mock_open.called
    assert not patch_process_single_operation.called


def test_process_single_file_failed_and_destination_does_not_exist(
    tmpdir, patch_process_single_operation, patch_os_remove, standard_handler
):
    patch_process_single_operation.return_value = identifiers.OperationResult.FAILED
    patch_os_remove.side_effect = OSError
    source = tmpdir.join("source")
    source.write("some data")
    destination = tmpdir.join("destination")

    # Verify that nothing is raised when os.remove raises an OSError
    standard_handler.process_single_file(
        stream_args={"mode": "encrypt"}, source=str(source), destination=str(destination)
    )


@pytest.mark.parametrize(
    "source, destination, mode, suffix, output",
    (
        (
            os.path.join("source_dir", "source_filename"),
            "destination_dir",
            "encrypt",
            None,
            os.path.join("destination_dir", "source_filename.encrypted"),
        ),
        (
            os.path.join("source_dir", "source_filename.encrypted"),
            "destination_dir",
            "encrypt",
            None,
            os.path.join("destination_dir", "source_filename.encrypted.encrypted"),
        ),
        (
            os.path.join("source_dir", "source_filename"),
            "destination_dir",
            "decrypt",
            None,
            os.path.join("destination_dir", "source_filename.decrypted"),
        ),
        (
            os.path.join("source_dir", "source_filename.encrypted"),
            "destination_dir",
            "decrypt",
            None,
            os.path.join("destination_dir", "source_filename.encrypted.decrypted"),
        ),
        (
            os.path.join("source_dir", "source_filename"),
            "destination_dir",
            "decrypt-unsigned",
            None,
            os.path.join("destination_dir", "source_filename.decrypted"),
        ),
        (
            os.path.join("source_dir", "source_filename.encrypted"),
            "destination_dir",
            "decrypt-unsigned",
            None,
            os.path.join("destination_dir", "source_filename.encrypted.decrypted"),
        ),
        (
            os.path.join("source_dir", "source_filename"),
            "destination_dir",
            "encrypt",
            "CUSTOM_SUFFIX",
            os.path.join("destination_dir", "source_filenameCUSTOM_SUFFIX"),
        ),
        (
            os.path.join("source_dir", "source_filename"),
            "destination_dir",
            "decrypt",
            "CUSTOM_SUFFIX",
            os.path.join("destination_dir", "source_filenameCUSTOM_SUFFIX"),
        ),
        (
            os.path.join("source_dir", "source_filename"),
            "destination_dir",
            "decrypt-unsigned",
            "CUSTOM_SUFFIX",
            os.path.join("destination_dir", "source_filenameCUSTOM_SUFFIX"),
        ),
    ),
)
def test_output_filename(source, destination, mode, suffix, output):
    assert io_handling.output_filename(source, destination, mode, suffix) == output


@pytest.mark.parametrize(
    "source_root, destination_root, source_dir, output",
    (
        (
            "source_dir",
            "destination_dir",
            os.path.join("source_dir", "child_1"),
            os.path.join("destination_dir", "child_1"),
        ),
        (
            "source_dir",
            "destination_dir",
            os.path.join("source_dir", "child_1", "child_2", "child_3"),
            os.path.join("destination_dir", "child_1", "child_2", "child_3"),
        ),
        (
            os.path.join("source_dir", "actual_source_root"),
            "destination_dir",
            os.path.join("source_dir", "actual_source_root", "child_1"),
            os.path.join("destination_dir", "child_1"),
        ),
    ),
)
def test_output_dir(source_root, destination_root, source_dir, output):
    assert io_handling._output_dir(source_root, destination_root, source_dir) == output


def _mock_aws_encryption_sdk_stream_output(source, *args, **kwargs):
    source_filename = source.name
    suffix = source_filename.rsplit("_", 1)[-1]
    mock_stream = io.BytesIO(DATA + six.b(suffix))
    mock_stream.header = MagicMock(encryption_context=sentinel.encryption_context)
    return mock_stream


def test_process_dir(tmpdir, patch_aws_encryption_sdk_stream, patch_json_ready_header, standard_handler):
    patch_aws_encryption_sdk_stream.side_effect = _mock_aws_encryption_sdk_stream_output
    source = tmpdir.mkdir("source")
    source.mkdir("a")
    source.join("a", "target_a1").write(b"")
    source.join("a", "target_a2").write(b"")
    b_dir = source.mkdir("b")
    source.join("b", "target_b1").write(b"")
    source.join("b", "target_b2").write(b"")
    c_dir = b_dir.mkdir("c")
    b_dir.join("c", "target_c1").write(b"")
    b_dir.join("c", "target_c2").write(b"")
    e_dir = c_dir.mkdir("d").mkdir("e")
    e_dir.join("target_e1").write(b"")
    target = tmpdir.mkdir("target")

    standard_handler.process_dir(
        stream_args={"mode": "encrypt"}, source=str(source), destination=str(target), suffix=None
    )

    for filename, suffix in (
        (os.path.join(str(target), "a", "target_a1.encrypted"), b"a1"),
        (os.path.join(str(target), "a", "target_a2.encrypted"), b"a2"),
        (os.path.join(str(target), "b", "target_b1.encrypted"), b"b1"),
        (os.path.join(str(target), "b", "target_b2.encrypted"), b"b2"),
        (os.path.join(str(target), "b", "c", "target_c1.encrypted"), b"c1"),
        (os.path.join(str(target), "b", "c", "target_c2.encrypted"), b"c2"),
        (os.path.join(str(target), "b", "c", "d", "e", "target_e1.encrypted"), b"e1"),
    ):
        assert os.path.isfile(filename)
        with open(filename, "rb") as f:
            assert f.read() == DATA + suffix
