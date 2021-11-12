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
import logging
import os
import shlex

import aws_encryption_sdk
import pytest
import six
from aws_encryption_sdk.materials_managers import CommitmentPolicy
from mock import ANY, MagicMock, call, sentinel

import aws_encryption_sdk_cli
from aws_encryption_sdk_cli.exceptions import AWSEncryptionSDKCLIError, BadUserArgumentError
from aws_encryption_sdk_cli.internal.arg_parsing import CommitmentPolicyArgs
from aws_encryption_sdk_cli.internal.logging_utils import FORMAT_STRING, _KMSKeyRedactingFormatter
from aws_encryption_sdk_cli.internal.metadata import MetadataWriter

from .unit_test_utils import is_windows

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def patch_process_cli_request(mocker):
    mocker.patch.object(aws_encryption_sdk_cli, "process_cli_request")
    return aws_encryption_sdk_cli.process_cli_request


@pytest.fixture
def patch_iohandler(mocker):
    mocker.patch.object(aws_encryption_sdk_cli, "IOHandler")
    return aws_encryption_sdk_cli.IOHandler


def test_catch_bad_destination_requests_stdout():
    aws_encryption_sdk_cli._catch_bad_destination_requests("-")


def test_catch_bad_destination_requests_dir(tmpdir):
    aws_encryption_sdk_cli._catch_bad_destination_requests(str(tmpdir))


def test_catch_bad_destination_requests_file(tmpdir):
    destination = tmpdir.join("dir1", "dir2", "file")
    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli._catch_bad_destination_requests(str(destination))

    assert excinfo.match(r"If destination is a file, the immediate parent directory must already exist.")


def test_catch_bad_stdin_stdout_requests_same_pipe():
    aws_encryption_sdk_cli._catch_bad_stdin_stdout_requests("-", "-")


def build_same_files_and_dirs(tmpdir, source_is_symlink, dest_is_symlink, use_files):
    """Build temporary files or directories to test indication of same source and destination.

    :param bool source_is_symlink: Should the source be a symlink to the destination (both cannot be True)
    :param bool dest is symlink: Should the destination be a symlink to the source (both cannot be True)
    :param bool use_files: Should files be created (if False, directories are used instead)
    """
    if use_files:
        real = tmpdir.join("real")
        real.write("some data")
    else:
        real = tmpdir.mkdir("real")
    link = tmpdir.join("link")

    if source_is_symlink or dest_is_symlink:
        os.symlink(str(real), str(link))

        if source_is_symlink:
            return str(link), str(real)

        if dest_is_symlink:
            return str(real), str(link)

    return str(real), str(real)


def build_same_file_and_dir_test_cases():
    if is_windows():
        return [(False, False, True), (False, False, False)]

    test_cases = []
    for use_files in (True, False):
        test_cases.extend([(False, False, use_files), (True, False, use_files), (False, True, use_files)])
    return test_cases


@pytest.mark.parametrize("source_is_symlink, dest_is_symlink, use_files", build_same_file_and_dir_test_cases())
def test_catch_bad_stdin_stdout_requests_source_is_dest(tmpdir, source_is_symlink, dest_is_symlink, use_files):
    source, dest = build_same_files_and_dirs(tmpdir, source_is_symlink, dest_is_symlink, use_files)

    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli._catch_bad_stdin_stdout_requests(source, dest)

    excinfo.match(r"Destination and source cannot be the same")


def test_catch_bad_stdin_stdout_requests_stdin_dir(tmpdir):
    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli._catch_bad_stdin_stdout_requests("-", str(tmpdir))

    excinfo.match(r"Destination may not be a directory when source is stdin")


def test_catch_bad_file_and_directory_requests_multiple_source_nondir_destination(tmpdir):
    a = tmpdir.join("a")
    a.write("asdf")
    b = tmpdir.join("b")
    b.write("asdf")

    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli._catch_bad_file_and_directory_requests((str(a), str(b)), str(tmpdir.join("c")))

    excinfo.match(r"If operating on multiple sources, destination must be an existing directory")


def test_catch_bad_file_and_directory_requests_contains_dir(tmpdir):
    b = tmpdir.mkdir("b")

    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli._catch_bad_file_and_directory_requests((str(b),), str(tmpdir.join("c")))

    excinfo.match(r"If operating on a source directory, destination must be an existing directory")


def test_catch_bad_metadata_file_requests_metadata_and_output_are_stdout():
    metadata_writer = MetadataWriter(suppress_output=False)(output_file="-")

    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli._catch_bad_metadata_file_requests(metadata_writer, "-", "-")

    excinfo.match(r"Metadata output cannot be stdout when output is stdout")


def test_catch_bad_metadata_file_requests_metadata_metadata_is_stdout_but_output_is_not():
    metadata_writer = MetadataWriter(suppress_output=False)(output_file="-")

    aws_encryption_sdk_cli._catch_bad_metadata_file_requests(metadata_writer, "not-std-in", "not-std-out")


def test_catch_bad_metadata_file_requests_metadata_is_dir(tmpdir):
    metadata_writer = MetadataWriter(suppress_output=False)(output_file=str(tmpdir))

    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli._catch_bad_metadata_file_requests(metadata_writer, "-", "-")

    excinfo.match(r"Metadata output cannot be a directory")


def test_catch_bad_metadata_file_requests_metadata_is_not_stdout_but_input_and_output_are_pipes(tmpdir):
    metadata_writer = MetadataWriter(suppress_output=False)(output_file=str(tmpdir.join("metadata")))

    aws_encryption_sdk_cli._catch_bad_metadata_file_requests(metadata_writer, "-", "-")


def test_catch_bad_metadata_file_requests_metadata_all_are_unique_files(tmpdir):
    source = tmpdir.join("source")
    metadata_file = tmpdir.join("metadata")
    destination = tmpdir.join("destination")

    metadata_writer = MetadataWriter(suppress_output=False)(output_file=str(metadata_file))

    aws_encryption_sdk_cli._catch_bad_metadata_file_requests(metadata_writer, str(source), str(destination))


def test_catch_bad_metadata_file_requests_metadata_is_empty(tmpdir):
    metadata_writer = MetadataWriter(suppress_output=False)(output_file="")
    # __call__ resolves empty output file to current directory
    metadata_writer.output_file = ""

    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli._catch_bad_metadata_file_requests(metadata_writer, "", "")

    excinfo.match("Metadata output file name cannot be empty")


def build_bad_metadata_file_requests():
    bad_requests = [(False, False, "source"), (False, False, "dest")]
    if not is_windows():
        bad_requests.extend(
            [(True, False, "source"), (False, True, "source"), (True, False, "dest"), (False, True, "dest")]
        )
    return bad_requests


@pytest.mark.parametrize("metadata_is_symlink, match_is_symlink, match", build_bad_metadata_file_requests())
def test_catch_bad_metadata_file_requests_metadata_is_source_or_dest(
    tmpdir, metadata_is_symlink, match_is_symlink, match
):
    if match == "source":
        source, metadata_file = build_same_files_and_dirs(tmpdir, metadata_is_symlink, match_is_symlink, True)
        destination = tmpdir.join("destination")
    else:
        source = tmpdir.join("source")
        destination, metadata_file = build_same_files_and_dirs(tmpdir, metadata_is_symlink, match_is_symlink, True)

    metadata_writer = MetadataWriter(suppress_output=False)(output_file=str(metadata_file))

    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli._catch_bad_metadata_file_requests(metadata_writer, str(source), str(destination))

    excinfo.match(r"Metadata output file cannot be the input or output")


@pytest.mark.parametrize("match", ("input", "output"))
def test_catch_bad_metadata_file_requests_metadata_in_source_or_dest_dir(tmpdir, match):
    source = tmpdir.mkdir("source")
    destination = tmpdir.mkdir("destination")
    if match == "input":
        metadata_file = source.join("metadata")
    else:
        metadata_file = destination.join("metadata")

    metadata_writer = MetadataWriter(suppress_output=False)(output_file=str(metadata_file))

    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli._catch_bad_metadata_file_requests(metadata_writer, str(source), str(destination))

    excinfo.match(r"Metadata output file cannot be in the {} directory".format(match))


@pytest.mark.parametrize("source_is_symlink, dest_is_symlink, use_files", build_same_file_and_dir_test_cases())
def test_process_cli_request_source_is_destination(tmpdir, source_is_symlink, dest_is_symlink, use_files):
    source, dest = build_same_files_and_dirs(tmpdir, source_is_symlink, dest_is_symlink, use_files)

    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli.process_cli_request(
            stream_args={"mode": "encrypt"},
            parsed_args=MagicMock(input=source, output=dest, recursive=True, interactive=False, no_overwrite=False),
        )
    excinfo.match(r"Destination and source cannot be the same")


def test_process_cli_request_source_dir_nonrecursive(tmpdir, patch_iohandler):
    source = tmpdir.mkdir("source")
    destination = tmpdir.mkdir("destination")
    metadata_writer = MetadataWriter(True)()
    aws_encryption_sdk_cli.process_cli_request(
        stream_args=sentinel.stream_args,
        parsed_args=MagicMock(
            input=str(source),
            output=str(destination),
            recursive=False,
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite,
            metadata_output=metadata_writer,
            decode=sentinel.decode_input,
            encode=sentinel.encode_output,
            encryption_context=sentinel.encryption_context,
            required_encryption_context_keys=sentinel.required_keys,
            commitment_policy=CommitmentPolicyArgs.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            buffer=sentinel.buffer_output,
            max_encrypted_data_keys=None,
        ),
    )

    patch_iohandler.assert_called_once_with(
        metadata_writer=metadata_writer,
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite,
        decode_input=sentinel.decode_input,
        encode_output=sentinel.encode_output,
        required_encryption_context=sentinel.encryption_context,
        required_encryption_context_keys=sentinel.required_keys,
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        buffer_output=sentinel.buffer_output,
        max_encrypted_data_keys=None,
    )
    assert not patch_iohandler.return_value.process_single_operation.called
    assert not patch_iohandler.return_value.process_dir.called
    assert not patch_iohandler.return_value.process_single_file.called


def test_process_cli_request_no_commitment_policy(tmpdir, patch_iohandler):
    source = tmpdir.mkdir("source")
    destination = tmpdir.mkdir("destination")
    metadata_writer = MetadataWriter(True)()
    aws_encryption_sdk_cli.process_cli_request(
        stream_args=sentinel.stream_args,
        parsed_args=MagicMock(
            input=str(source),
            output=str(destination),
            recursive=False,
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite,
            metadata_output=metadata_writer,
            decode=sentinel.decode_input,
            encode=sentinel.encode_output,
            encryption_context=sentinel.encryption_context,
            required_encryption_context_keys=sentinel.required_keys,
            commitment_policy=None,
            buffer=sentinel.buffer_output,
            max_encrypted_data_keys=None,
        ),
    )

    patch_iohandler.assert_called_once_with(
        metadata_writer=metadata_writer,
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite,
        decode_input=sentinel.decode_input,
        encode_output=sentinel.encode_output,
        required_encryption_context=sentinel.encryption_context,
        required_encryption_context_keys=sentinel.required_keys,
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        buffer_output=sentinel.buffer_output,
        max_encrypted_data_keys=None,
    )
    assert not patch_iohandler.return_value.process_single_operation.called
    assert not patch_iohandler.return_value.process_dir.called
    assert not patch_iohandler.return_value.process_single_file.called


def test_process_cli_request_source_dir_destination_nondir(tmpdir):
    source = tmpdir.mkdir("source")
    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli.process_cli_request(
            stream_args={"mode": "encrypt"},
            parsed_args=MagicMock(
                input=str(source),
                output=str(tmpdir.join("destination")),
                recursive=True,
                interactive=False,
                no_overwrite=False,
                decode=False,
                encode=False,
                metadata_output=MetadataWriter(True)(),
                encryption_context={},
                required_encryption_context_keys=[],
                commitment_policy=CommitmentPolicyArgs.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
                buffer=False,
                max_encrypted_data_keys=None,
            ),
        )
    excinfo.match(r"If operating on a source directory, destination must be an existing directory")


def test_process_cli_request_source_dir_destination_dir(tmpdir, patch_iohandler):
    source = tmpdir.mkdir("source_dir")
    destination = tmpdir.mkdir("destination_dir")
    aws_encryption_sdk_cli.process_cli_request(
        stream_args=sentinel.stream_args,
        parsed_args=MagicMock(
            input=str(source),
            output=str(destination),
            recursive=True,
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite,
            suffix=sentinel.suffix,
            decode=sentinel.decode_input,
            encode=sentinel.encode_output,
            metadata_output=MetadataWriter(True)(),
            commitment_policy=CommitmentPolicyArgs.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            buffer=sentinel.buffer_output,
        ),
    )

    patch_iohandler.return_value.process_dir.assert_called_once_with(
        stream_args=sentinel.stream_args, source=str(source), destination=str(destination), suffix=sentinel.suffix
    )
    assert not patch_iohandler.return_value.process_single_file.called
    assert not patch_iohandler.return_value.process_single_operation.called


def test_process_cli_request_source_stdin_destination_dir(tmpdir):
    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli.process_cli_request(
            stream_args={"mode": "encrypt"},
            parsed_args=MagicMock(
                input="-", output=str(tmpdir), recursive=False, interactive=False, no_overwrite=False
            ),
        )
    excinfo.match(r"Destination may not be a directory when source is stdin")


def test_process_cli_request_source_stdin(tmpdir, patch_iohandler):
    destination = tmpdir.join("destination")
    mock_parsed_args = MagicMock(
        input="-",
        output=str(destination),
        recursive=False,
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite,
        decode=sentinel.decode_input,
        encode=sentinel.encode_output,
        metadata_output=MetadataWriter(True)(),
        commitment_policy=CommitmentPolicyArgs.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        buffer=sentinel.buffer_output,
    )
    aws_encryption_sdk_cli.process_cli_request(stream_args=sentinel.stream_args, parsed_args=mock_parsed_args)
    assert not patch_iohandler.return_value.process_dir.called
    assert not patch_iohandler.return_value.process_single_file.called
    patch_iohandler.return_value.process_single_operation.assert_called_once_with(
        stream_args=sentinel.stream_args, source="-", destination=str(destination)
    )


def test_process_cli_request_source_file_destination_dir(tmpdir, patch_iohandler):
    source = tmpdir.join("source")
    source.write("some data")
    destination = tmpdir.mkdir("destination")
    aws_encryption_sdk_cli.process_cli_request(
        stream_args={"mode": sentinel.mode},
        parsed_args=MagicMock(
            input=str(source),
            output=str(destination),
            recursive=False,
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite,
            suffix="CUSTOM_SUFFIX",
            decode=sentinel.decode_input,
            encode=sentinel.encode_output,
            metadata_output=MetadataWriter(True)(),
            commitment_policy=CommitmentPolicyArgs.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            buffer=sentinel.buffer_output,
        ),
    )
    assert not patch_iohandler.return_value.process_dir.called
    assert not patch_iohandler.return_value.process_single_operation.called
    patch_iohandler.return_value.process_single_file.assert_called_once_with(
        stream_args={"mode": sentinel.mode},
        source=str(source),
        destination=str(destination.join("sourceCUSTOM_SUFFIX")),
    )


def test_process_cli_request_source_file_destination_file(tmpdir, patch_iohandler):
    source = tmpdir.join("source")
    source.write("some data")
    destination = tmpdir.join("destination")

    aws_encryption_sdk_cli.process_cli_request(
        stream_args={"mode": sentinel.mode},
        parsed_args=MagicMock(
            input=str(source),
            output=str(destination),
            recursive=False,
            interactive=sentinel.interactive,
            no_overwrite=sentinel.no_overwrite,
            decode=sentinel.decode_input,
            encode=sentinel.encode_output,
            metadata_output=MetadataWriter(True)(),
            commitment_policy=CommitmentPolicyArgs.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            buffer=sentinel.buffer_output,
        ),
    )
    assert not patch_iohandler.return_value.process_dir.called
    assert not patch_iohandler.return_value.process_single_operation.called
    patch_iohandler.return_value.process_single_file.assert_called_once_with(
        stream_args={"mode": sentinel.mode}, source=str(source), destination=str(destination)
    )


def test_process_cli_request_invalid_source(tmpdir):
    target = os.path.join(str(tmpdir), "test_targets.*")
    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli.process_cli_request(
            stream_args={},
            parsed_args=MagicMock(
                input=target,
                output="a specific destination",
                recursive=False,
                interactive=False,
                no_overwrite=False,
                decode=False,
                encode=False,
                metadata_output=MetadataWriter(True)(),
                encryption_context={},
                required_encryption_context_keys=[],
                commitment_policy=CommitmentPolicyArgs.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
                buffer=False,
                max_encrypted_data_keys=None,
            ),
        )
    excinfo.match(r"Invalid source.  Must be a valid pathname pattern or stdin \(-\)")


def test_process_cli_request_globbed_source_non_directory_target(tmpdir, patch_iohandler):
    plaintext_dir = tmpdir.mkdir("plaintext")
    test_file = plaintext_dir.join("testing.aa")
    test_file.write(b"some data here!")
    test_file = plaintext_dir.join("testing.bb")
    test_file.write(b"some data here!")
    ciphertext_dir = tmpdir.mkdir("ciphertext")
    target_file = ciphertext_dir.join("target_file")
    source = os.path.join(str(plaintext_dir), "testing.*")

    with pytest.raises(BadUserArgumentError) as excinfo:
        aws_encryption_sdk_cli.process_cli_request(
            stream_args={"mode": "encrypt"},
            parsed_args=MagicMock(
                commitment_policy=CommitmentPolicyArgs.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
                input=source,
                output=str(target_file),
                recursive=False,
                interactive=False,
                no_overwrite=False,
            ),
        )

    excinfo.match("If operating on multiple sources, destination must be an existing directory")
    assert not patch_iohandler.return_value.process_dir.called
    assert not patch_iohandler.return_value.process_single_file.called


def test_process_cli_request_source_contains_directory_nonrecursive(tmpdir, patch_iohandler):
    plaintext_dir = tmpdir.mkdir("plaintext")
    test_file_a = plaintext_dir.join("testing.aa")
    test_file_a.write(b"some data here!")
    test_file_c = plaintext_dir.join("testing.cc")
    test_file_c.write(b"some data here!")
    plaintext_dir.mkdir("testing.bb")
    ciphertext_dir = tmpdir.mkdir("ciphertext")
    source = os.path.join(str(plaintext_dir), "testing.*")

    aws_encryption_sdk_cli.process_cli_request(
        stream_args={"mode": "encrypt"},
        parsed_args=MagicMock(
            input=source,
            output=str(ciphertext_dir),
            recursive=False,
            interactive=False,
            no_overwrite=False,
            encode=False,
            decode=False,
            metadata_output=MetadataWriter(True)(),
            commitment_policy=CommitmentPolicyArgs.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
            buffer=False,
        ),
    )

    assert not patch_iohandler.return_value.process_dir.called
    patch_iohandler.return_value.process_single_file.assert_has_calls(
        calls=[
            call(stream_args={"mode": "encrypt"}, source=str(source_file), destination=ANY)
            for source_file in (test_file_a, test_file_c)
        ],
        any_order=True,
    )


@pytest.mark.parametrize(
    "args, stream_args",
    (
        (
            MagicMock(
                action=sentinel.mode,
                encryption_context=None,
                algorithm=None,
                frame_length=None,
                max_length=None,
                max_encrypted_data_keys=None,
            ),
            {"materials_manager": sentinel.materials_manager, "mode": sentinel.mode},
        ),
        (
            MagicMock(
                action=sentinel.mode,
                encryption_context=None,
                algorithm=None,
                frame_length=None,
                max_length=sentinel.max_length,
                max_encrypted_data_keys=None,
            ),
            {
                "materials_manager": sentinel.materials_manager,
                "mode": sentinel.mode,
                "max_body_length": sentinel.max_length,
            },
        ),
        (
            MagicMock(
                action=sentinel.mode,
                encryption_context=None,
                algorithm=None,
                frame_length=None,
                max_length=None,
                max_encrypted_data_keys=sentinel.max_encrypted_data_keys,
            ),
            {
                "materials_manager": sentinel.materials_manager,
                "mode": sentinel.mode,
            },
        ),
        (
            MagicMock(
                action=sentinel.mode,
                encryption_context=None,
                algorithm=None,
                frame_length=None,
                max_length=None,
                max_encrypted_data_keys=None,
            ),
            {"materials_manager": sentinel.materials_manager, "mode": sentinel.mode},
        ),
        (
            MagicMock(
                action=sentinel.mode,
                encryption_context=sentinel.encryption_context,
                algorithm="AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384",
                frame_length=sentinel.frame_length,
                max_length=None,
                max_encrypted_data_keys=None,
            ),
            {"materials_manager": sentinel.materials_manager, "mode": sentinel.mode},
        ),
        (
            MagicMock(
                action="encrypt",
                encryption_context={"encryption": "context", "with": "keys"},
                algorithm="AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384",
                frame_length=sentinel.frame_length,
                max_length=None,
                max_encrypted_data_keys=None,
            ),
            {
                "materials_manager": sentinel.materials_manager,
                "mode": "encrypt",
                "encryption_context": {"encryption": "context", "with": "keys"},
                "algorithm": aws_encryption_sdk.Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                "frame_length": sentinel.frame_length,
            },
        ),
        (
            MagicMock(
                action="encrypt",
                encryption_context={},
                algorithm="AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384",
                frame_length=sentinel.frame_length,
                max_length=None,
                max_encrypted_data_keys=None,
            ),
            {
                "materials_manager": sentinel.materials_manager,
                "mode": "encrypt",
                "algorithm": aws_encryption_sdk.Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                "frame_length": sentinel.frame_length,
                "encryption_context": {},
            },
        ),
        (
            MagicMock(
                action="encrypt",
                encryption_context={"encryption": "context", "with": "keys"},
                algorithm=None,
                frame_length=sentinel.frame_length,
                max_length=None,
                max_encrypted_data_keys=None,
            ),
            {
                "materials_manager": sentinel.materials_manager,
                "mode": "encrypt",
                "encryption_context": {"encryption": "context", "with": "keys"},
                "frame_length": sentinel.frame_length,
            },
        ),
        (
            MagicMock(
                action="encrypt",
                encryption_context={"encryption": "context", "with": "keys"},
                algorithm="AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384",
                frame_length=None,
                max_length=None,
                max_encrypted_data_keys=None,
            ),
            {
                "materials_manager": sentinel.materials_manager,
                "mode": "encrypt",
                "encryption_context": {"encryption": "context", "with": "keys"},
                "algorithm": aws_encryption_sdk.Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
            },
        ),
    ),
)
def test_stream_kwargs_from_args(args, stream_args):
    assert aws_encryption_sdk_cli.stream_kwargs_from_args(args, sentinel.materials_manager) == stream_args


@pytest.fixture
def patch_for_cli(mocker):
    mocker.patch.object(aws_encryption_sdk_cli, "parse_args")
    aws_encryption_sdk_cli.parse_args.return_value = MagicMock(
        version=False,
        verbosity=sentinel.verbosity,
        quiet=sentinel.quiet,
        wrapping_keys=sentinel.wrapping_keys,
        caching=sentinel.caching_config,
        input=sentinel.input,
        output=sentinel.output,
        recursive=sentinel.recursive,
        interactive=sentinel.interactive,
        no_overwrite=sentinel.no_overwrite,
        suffix=sentinel.suffix,
        discovery=sentinel.discovery,
        discovery_account=sentinel.discovery_account,
        discovery_partition=sentinel.discovery_partition,
        decode=sentinel.decode_input,
        encode=sentinel.encode_output,
        buffer=sentinel.buffer_output,
    )
    mocker.patch.object(aws_encryption_sdk_cli, "setup_logger")
    mocker.patch.object(aws_encryption_sdk_cli, "build_crypto_materials_manager_from_args")
    aws_encryption_sdk_cli.build_crypto_materials_manager_from_args.return_value = sentinel.crypto_materials_manager
    mocker.patch.object(aws_encryption_sdk_cli, "stream_kwargs_from_args")
    aws_encryption_sdk_cli.stream_kwargs_from_args.return_value = sentinel.stream_args
    mocker.patch.object(aws_encryption_sdk_cli, "process_cli_request")


def test_cli(patch_for_cli):
    test = aws_encryption_sdk_cli.cli(sentinel.raw_args)

    aws_encryption_sdk_cli.parse_args.assert_called_once_with(sentinel.raw_args)
    aws_encryption_sdk_cli.setup_logger.assert_called_once_with(sentinel.verbosity, sentinel.quiet)
    aws_encryption_sdk_cli.build_crypto_materials_manager_from_args.assert_called_once_with(
        key_providers_config=sentinel.wrapping_keys, caching_config=sentinel.caching_config
    )
    aws_encryption_sdk_cli.stream_kwargs_from_args.assert_called_once_with(
        aws_encryption_sdk_cli.parse_args.return_value, sentinel.crypto_materials_manager
    )
    aws_encryption_sdk_cli.process_cli_request.assert_called_once_with(
        sentinel.stream_args, aws_encryption_sdk_cli.parse_args.return_value
    )
    assert test is None


def test_cli_local_error(patch_for_cli):
    aws_encryption_sdk_cli.process_cli_request.side_effect = AWSEncryptionSDKCLIError(sentinel.error_message)
    test = aws_encryption_sdk_cli.cli()

    assert test is sentinel.error_message


def test_cli_unknown_error(patch_for_cli):
    aws_encryption_sdk_cli.process_cli_request.side_effect = Exception()
    test = aws_encryption_sdk_cli.cli()

    assert test.startswith("Encountered unexpected ")


def kms_redacting_logger_stream(log_level):
    output_stream = six.StringIO()
    formatter = _KMSKeyRedactingFormatter(FORMAT_STRING)
    handler = logging.StreamHandler(stream=output_stream)
    handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.setLevel(log_level)
    logger.addHandler(handler)
    return output_stream


@pytest.mark.parametrize(
    "log_level, requested_log_level", ((logging.WARNING, ""), (logging.INFO, "-v"), (logging.DEBUG, "-vv"))
)
def test_cli_unknown_error_capture_stacktrace(patch_process_cli_request, tmpdir, log_level, requested_log_level):
    log_stream = kms_redacting_logger_stream(log_level)
    plaintext = tmpdir.join("plaintext")
    plaintext.write("some data")
    message = "THIS IS A REASONABLY UNIQUE ERROR MESSAGE #&*Y(HJFIWE"
    patch_process_cli_request.side_effect = Exception(message)

    test = aws_encryption_sdk_cli.cli(
        shlex.split(
            "-Sd -i "
            + str(plaintext)
            + " -o "
            + str(tmpdir.join("ciphertext"))
            + " "
            + requested_log_level
            + " -w discovery=true region=us-west-2"
        )
    )

    all_logs = log_stream.getvalue()
    assert test.startswith("Encountered unexpected error: increase verbosity to see details.")
    assert message in test
    if log_level <= logging.DEBUG:
        assert "Traceback" in all_logs
        assert message in all_logs
    else:
        assert "Traceback" not in all_logs
        assert message not in all_logs
