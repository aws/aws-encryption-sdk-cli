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
"""Helper functions for handling all input and output for this CLI."""
from __future__ import division

import copy
import logging
import os
import sys

import attr
import aws_encryption_sdk
import six
from aws_encryption_sdk.materials_managers import CommitmentPolicy  # noqa pylint: disable=unused-import
from base64io import Base64IO

from aws_encryption_sdk_cli.exceptions import BadUserArgumentError
from aws_encryption_sdk_cli.internal.identifiers import OUTPUT_SUFFIX, OperationResult
from aws_encryption_sdk_cli.internal.logging_utils import LOGGER_NAME
from aws_encryption_sdk_cli.internal.metadata import MetadataWriter, json_ready_header, json_ready_header_auth

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import IO, Dict, List, Type, Union, cast  # noqa pylint: disable=unused-import

    from aws_encryption_sdk_cli.internal.mypy_types import SOURCE, STREAM_KWARGS  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    cast = lambda typ, val: val  # noqa pylint: disable=invalid-name
    IO = None  # type: ignore
    # We only actually need the other imports when running the mypy checks

__all__ = ("IOHandler", "output_filename")
_LOGGER = logging.getLogger(LOGGER_NAME)


def _stdout():
    # type: () -> IO
    """Returns the appropriate stdout to use for incremental writes.

    :returns: stdout buffer
    """
    if six.PY3:
        return sys.stdout.buffer
    return sys.stdout


def _stdin():
    # type: () -> IO
    """Returns the appropriate stdin to use for incremental writes.

    :returns: stdin buffer
    """
    if six.PY3:
        return sys.stdin.buffer
    return sys.stdin


def _file_exists_error():
    # type: () -> Type[Exception]
    """Returns the appropriate error that ``os.makedirs`` returns if the output directory
    already exists.
    """
    if six.PY3:
        return FileExistsError
    return OSError


def _ensure_dir_exists(filename):
    # type: (str) -> None
    """Creates a directory tree if it does not already exist.

    :param str filename: Full path to file in destination directory
    """
    dest_final_dir = filename.rsplit(os.sep, 1)[0]
    if dest_final_dir == filename:
        # File is in current directory
        _LOGGER.debug("Target dir is current dir")
        return
    try:
        os.makedirs(dest_final_dir)
    except _file_exists_error():
        # os.makedirs(... exist_ok=True) does not work in 2.7
        pass
    else:
        _LOGGER.info("Created directory: %s", dest_final_dir)


def _encoder(stream, should_base64):
    # type: (IO, bool) -> Union[IO, Base64IO]
    """Wraps a stream in either a Base64IO transformer or results stream if wrapping is not requested.

    :param stream: Stream to wrap
    :type stream: file-like object
    :param bool should_base64: Should the stream be wrapped with Base64IO
    :returns: wrapped stream
    :rtype: io.IOBase
    """
    if should_base64:
        return Base64IO(stream)
    return stream


def output_filename(source_filename, destination_dir, mode, suffix):
    # type: (str, str, str, str) -> str
    """Duplicates the source filename in the destination directory, adding or stripping
    a suffix as needed.

    :param str source_filename: Full file path to source file
    :param str destination_dir: Full file path to destination directory
    :param str mode: Operating mode (encrypt/decrypt)
    :param str suffix: Suffix to append to output filename
    :returns: Full file path of new destination file in destination directory
    :rtype: str
    """
    if suffix is None:
        suffix = OUTPUT_SUFFIX[mode]
    else:
        _LOGGER.debug('Using custom suffix "%s" to create output file', suffix)
    filename = source_filename.rsplit(os.sep, 1)[-1]
    _LOGGER.debug("Duplicating filename %s into %s", filename, destination_dir)
    return os.path.join(destination_dir, filename) + suffix


def _output_dir(source_root, destination_root, source_dir):
    # type: (str, str, str) -> str
    """Duplicates the source child directory structure into the output directory root.

    :param str source_root: Root of source directory
    :param str destination_root: Root of destination directory
    :param str source_dir: Actual directory of source file (child of source_root)
    """
    root_len = len(source_root)
    suffix = source_dir[root_len:].lstrip(os.path.sep)
    return os.path.join(destination_root, suffix)


def _is_decrypt_mode(mode):
    # type: (str) -> bool
    """
    Determines whether the provided mode does decryption

    :param str filepath: Full file path to file in question
    :rtype: bool
    """
    if mode in ("decrypt", "decrypt-unsigned"):
        return True
    if mode == "encrypt":
        return False
    raise BadUserArgumentError("Mode {mode} has not been implemented".format(mode=mode))


@attr.s(hash=False, init=False)
class IOHandler(object):
    """Common handler for all IO operations. Holds common configuration values used for all
    operations.

    :param metadata_writer: File-like to which metadata should be written
    :type metadata_writer: aws_encryption_sdk_cli.internal.metadata.MetadataWriter
    :param bool interactive: Should prompt before overwriting existing files
    :param bool no_overwrite: Should never overwrite existing files
    :param bool decode_input: Should input be base64 decoded before operation
    :param bool encode_output: Should output be base64 encoded after operation
    :param bool buffer_output: Should buffer entire output before releasing to destination
    :param dict required_encryption_context: Encryption context key-value pairs to require
    :param list required_encryption_context_keys: Encryption context keys to require
    """

    metadata_writer = attr.ib(validator=attr.validators.instance_of(MetadataWriter))
    interactive = attr.ib(validator=attr.validators.instance_of(bool))
    no_overwrite = attr.ib(validator=attr.validators.instance_of(bool))
    decode_input = attr.ib(validator=attr.validators.instance_of(bool))
    encode_output = attr.ib(validator=attr.validators.instance_of(bool))
    buffer_output = attr.ib(validator=attr.validators.instance_of(bool))
    required_encryption_context = attr.ib(validator=attr.validators.instance_of(dict))
    required_encryption_context_keys = attr.ib(
        validator=attr.validators.instance_of(list)
    )  # noqa pylint: disable=invalid-name

    def __init__(  # noqa pylint: disable=too-many-arguments
        self,
        metadata_writer,  # type: MetadataWriter
        interactive,  # type: bool
        no_overwrite,  # type: bool
        decode_input,  # type: bool
        encode_output,  # type: bool
        required_encryption_context,  # type: Dict[str, str]
        required_encryption_context_keys,  # type: List[str]
        commitment_policy,  # type: CommitmentPolicy
        buffer_output,
        max_encrypted_data_keys,  # type: Union[None, int]
    ):
        # type: (...) -> None
        """Workaround pending resolution of attrs/mypy interaction.
        https://github.com/python/mypy/issues/2088
        https://github.com/python-attrs/attrs/issues/215
        """
        self.metadata_writer = metadata_writer
        self.interactive = interactive
        self.no_overwrite = no_overwrite
        self.decode_input = decode_input
        self.encode_output = encode_output
        self.required_encryption_context = required_encryption_context
        self.required_encryption_context_keys = required_encryption_context_keys  # pylint: disable=invalid-name
        self.buffer_output = buffer_output
        self.client = aws_encryption_sdk.EncryptionSDKClient(
            commitment_policy=commitment_policy,
            max_encrypted_data_keys=max_encrypted_data_keys,
        )
        attr.validate(self)

    def _single_io_write(self, stream_args, source, destination_writer):
        # type: (STREAM_KWARGS, IO, IO) -> OperationResult
        """Performs the actual write operations for a single operation.

        :param dict stream_args: kwargs to pass to `aws_encryption_sdk.stream`
        :param source: source to write
        :type source: file-like object
        :param destination_writer: destination object to which to write
        :type destination_writer: file-like object
        :returns: OperationResult stating whether the file was written
        :rtype: aws_encryption_sdk_cli.internal.identifiers.OperationResult
        """
        with _encoder(source, self.decode_input) as _source, _encoder(
            destination_writer, self.encode_output
        ) as _destination:  # noqa pylint: disable=line-too-long
            with self.client.stream(source=_source, **stream_args) as handler, self.metadata_writer as metadata:
                metadata_kwargs = dict(
                    mode=stream_args["mode"],
                    input=source.name,
                    output=destination_writer.name,
                    header=json_ready_header(handler.header),
                )
                try:
                    header_auth = handler.header_auth
                except AttributeError:
                    # EncryptStream doesn't expose the header auth at this time
                    pass
                else:
                    metadata_kwargs["header_auth"] = json_ready_header_auth(header_auth)

                if _is_decrypt_mode(str(stream_args["mode"])):
                    discovered_ec = handler.header.encryption_context
                    missing_keys = set(self.required_encryption_context_keys).difference(set(discovered_ec.keys()))
                    missing_pairs = set(self.required_encryption_context.items()).difference(set(discovered_ec.items()))
                    if missing_keys or missing_pairs:
                        _LOGGER.warning(
                            "Skipping decrypt because discovered encryption context did not match required elements."
                        )
                        metadata_kwargs.update(
                            dict(
                                skipped=True,
                                reason="Missing encryption context key or value",
                                missing_encryption_context_keys=list(missing_keys),
                                missing_encryption_context_pairs=list(missing_pairs),
                            )
                        )
                        metadata.write_metadata(**metadata_kwargs)
                        return OperationResult.FAILED_VALIDATION

                metadata.write_metadata(**metadata_kwargs)
                if self.buffer_output:
                    _destination.write(handler.read())
                else:
                    for chunk in handler:
                        _destination.write(chunk)
                        _destination.flush()
        return OperationResult.SUCCESS

    def process_single_operation(self, stream_args, source, destination):
        # type: (STREAM_KWARGS, SOURCE, str) -> OperationResult
        """Processes a single encrypt/decrypt operation given a pre-loaded source.

        :param dict stream_args: kwargs to pass to `aws_encryption_sdk.stream`
        :param source: source to write
        :type source: str or file-like object
        :param str destination: destination identifier
        :returns: OperationResult stating whether the file was written
        :rtype: aws_encryption_sdk_cli.internal.identifiers.OperationResult
        """
        if destination == "-":
            destination_writer = _stdout()
        else:
            if not self._should_write_file(destination):
                return OperationResult.SKIPPED
            _ensure_dir_exists(destination)
            # pylint: disable=consider-using-with
            destination_writer = open(os.path.abspath(destination), "wb")

        if source == "-":
            source = _stdin()

        try:
            return self._single_io_write(
                stream_args=stream_args, source=cast(IO, source), destination_writer=destination_writer
            )
        finally:
            destination_writer.close()

    def _should_write_file(self, filepath):
        # type: (str) -> bool
        """Determines whether a specific file should be written.

        :param str filepath: Full file path to file in question
        :rtype: bool
        """
        if not os.path.isfile(filepath):
            # The file does not exist, nothing to overwrite
            return True

        if self.no_overwrite:
            # The file exists and the caller specifically asked us not to overwrite anything
            _LOGGER.warning('Skipping existing output file because of "no overwrite" option: %s', filepath)
            return False

        if self.interactive:
            # The file exists and the caller asked us to be consulted on action before overwriting
            decision = six.moves.input(  # type: ignore # six.moves confuses mypy
                'Overwrite existing output file "{}" with new contents? [y/N]:'.format(filepath)
            )
            try:
                if decision.lower()[0] == "y":
                    _LOGGER.warning("Overwriting existing output file based on interactive user decision: %s", filepath)
                    return True
                return False
            except IndexError:
                # No input is interpreted as 'do not overwrite'
                _LOGGER.warning("Skipping existing output file based on interactive user decision: %s", filepath)
                return False

        # If we get to this point, the file exists and we should overwrite it
        _LOGGER.warning("Overwriting existing output file because no action was specified otherwise: %s", filepath)
        return True

    def process_single_file(self, stream_args, source, destination):
        # type: (STREAM_KWARGS, str, str) -> None
        """Processes a single encrypt/decrypt operation on a source file.

        :param dict stream_args: kwargs to pass to `aws_encryption_sdk.stream`
        :param str source: Full file path to source file
        :param str destination: Full file path to destination file
        """
        if os.path.realpath(source) == os.path.realpath(destination):
            # File source, directory destination, empty suffix:
            _LOGGER.warning("Skipping because the source (%s) and destination (%s) are the same", source, destination)
            return

        _LOGGER.info("%sing file %s to %s", stream_args["mode"], source, destination)

        _stream_args = copy.copy(stream_args)
        # Because we can actually know size for files and Base64IO does not support seeking,
        # set the source length manually for files. This allows enables data key caching when
        # Base64-decoding a source file.
        source_file_size = os.path.getsize(source)
        if self.decode_input and not self.encode_output:
            _stream_args["source_length"] = int(source_file_size * (3 / 4))
        else:
            _stream_args["source_length"] = source_file_size

        try:
            with open(os.path.abspath(source), "rb") as source_reader:
                operation_result = self.process_single_operation(
                    stream_args=_stream_args, source=source_reader, destination=destination
                )
        except Exception:  # pylint: disable=broad-except
            operation_result = OperationResult.FAILED
            raise
        finally:
            if operation_result.needs_cleanup and destination != "-":  # pylint: disable=no-member
                _LOGGER.warning("Operation failed: deleting output file: %s", destination)
                try:
                    os.remove(destination)
                except OSError:
                    # if the file doesn't exist that's ok too
                    pass

    def process_dir(self, stream_args, source, destination, suffix):
        # type: (STREAM_KWARGS, str, str, str) -> None
        """Processes encrypt/decrypt operations on all files in a directory tree.

        :param dict stream_args: kwargs to pass to `aws_encryption_sdk.stream`
        :param str source: Full file path to source directory root
        :param str destination: Full file path to destination directory root
        :param str suffix: Suffix to append to output filename
        """
        _LOGGER.debug("%sing directory %s to %s", stream_args["mode"], source, destination)
        for base_dir, _dirs, files in os.walk(source):
            for filename in files:
                source_filename = os.path.join(base_dir, filename)
                destination_dir = _output_dir(source_root=source, destination_root=destination, source_dir=base_dir)
                destination_filename = output_filename(
                    source_filename=source_filename,
                    destination_dir=destination_dir,
                    mode=str(stream_args["mode"]),
                    suffix=suffix,
                )
                self.process_single_file(
                    stream_args=stream_args, source=source_filename, destination=destination_filename
                )
