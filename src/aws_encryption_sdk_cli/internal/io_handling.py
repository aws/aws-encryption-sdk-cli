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
from typing import cast, IO, Type, Union  # noqa pylint: disable=unused-import

import aws_encryption_sdk
import six

from aws_encryption_sdk_cli.internal.encoding import Base64IO
from aws_encryption_sdk_cli.internal.identifiers import OUTPUT_SUFFIX
from aws_encryption_sdk_cli.internal.logging_utils import LOGGER_NAME
from aws_encryption_sdk_cli.internal.metadata import json_ready_header, json_ready_header_auth
from aws_encryption_sdk_cli.internal.metadata import MetadataWriter  # noqa pylint: disable=unused-import
from aws_encryption_sdk_cli.internal.mypy_types import SOURCE, STREAM_KWARGS  # noqa pylint: disable=unused-import

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
    """Returns the appropriate error that ``os.makedirs`` returns if the target directory
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
        _LOGGER.debug('Target dir is current dir')
        return
    try:
        os.makedirs(dest_final_dir)
    except _file_exists_error():
        # os.makedirs(... exist_ok=True) does not work in 2.7
        pass
    else:
        _LOGGER.info('Created directory: %s', dest_final_dir)


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


def _single_io_write(stream_args, source, destination_writer, decode_input, encode_output, metadata_writer):
    # type: (STREAM_KWARGS, IO, IO, bool, bool, MetadataWriter) -> None
    """Performs the actual write operations for a single operation.

    :param dict stream_args: kwargs to pass to `aws_encryption_sdk.stream`
    :param source: source to write
    :type source: file-like object
    :param destination_writer: destination object to which to write
    :type destination_writer: file-like object
    :param bool decode_input: Should input be base64 decoded before operation
    :param bool encode_output: Should output be base64 encoded after operation
    :param metadata_writer: File-like to which metadata should be written
    :type metadata_writer: aws_encryption_sdk_cli.internal.metadata.MetadataWriter
    """
    with _encoder(source, decode_input) as _source, _encoder(destination_writer, encode_output) as _destination:
        with aws_encryption_sdk.stream(source=_source, **stream_args) as handler, metadata_writer as metadata:
            metadata_kwargs = dict(
                mode=stream_args['mode'],
                input=source.name,
                output=destination_writer.name,
                header=json_ready_header(handler.header)
            )
            try:
                header_auth = handler.header_auth
                metadata_kwargs['header_auth'] = json_ready_header_auth(header_auth)
            except AttributeError:
                # EncryptStream doesn't expose the header auth at this time
                pass
            metadata.write_metadata(**metadata_kwargs)
            for chunk in handler:
                _destination.write(chunk)
                _destination.flush()


def process_single_operation(stream_args, source, destination, interactive, no_overwrite, decode_input, encode_output, metadata_writer):
    # type: (STREAM_KWARGS, SOURCE, str, bool, bool, bool, bool, MetadataWriter) -> None
    """Processes a single encrypt/decrypt operation given a pre-loaded source.

    :param dict stream_args: kwargs to pass to `aws_encryption_sdk.stream`
    :param source: source to write
    :type source: str or file-like object
    :param str destination: destination identifier
    :param bool interactive: Should prompt before overwriting existing files
    :param bool no_overwrite: Should never overwrite existing files
    :param bool decode_input: Should input be base64 decoded before operation
    :param bool encode_output: Should output be base64 encoded after operation
    :param metadata_writer: File-like to which metadata should be written
    :type metadata_writer: aws_encryption_sdk_cli.internal.metadata.MetadataWriter
    """
    if destination == '-':
        destination_writer = _stdout()
    else:
        if not _should_write_file(filepath=destination, interactive=interactive, no_overwrite=no_overwrite):
            return
        _ensure_dir_exists(destination)
        destination_writer = open(destination, 'wb')

    if source == '-':
        source_reader = _stdin()
    else:
        source_reader = cast(IO, source)

    with destination_writer:
        _single_io_write(
            stream_args=stream_args,
            source=source_reader,
            destination_writer=destination_writer,
            decode_input=decode_input,
            encode_output=encode_output,
            metadata_writer=metadata_writer
        )


def _should_write_file(filepath, interactive, no_overwrite):
    # type: (str, bool, bool) -> bool
    """Determines whether a specific file should be written.

    :param str filepath: Full file path to file in question
    :param bool interactive: Should prompt before overwriting existing files
    :param bool no_overwrite: Should never overwrite existing files
    :rtype: bool
    """
    if not os.path.isfile(filepath):
        # The file does not exist, nothing to overwrite
        return True

    if no_overwrite:
        # The file exists and the caller specifically asked us not to overwrite anything
        _LOGGER.warning('Skipping existing target file because of "no overwrite" option: %s', filepath)
        return False

    if interactive:
        # The file exists and the caller asked us to be consulted on action before overwriting
        decision = six.moves.input(  # type: ignore # six.moves confuses mypy
            'Overwrite existing target file "{}" with new contents? [y/N]:'.format(filepath)
        )
        try:
            if decision.lower()[0] == 'y':
                _LOGGER.warning('Overwriting existing target file based on interactive user decision: %s', filepath)
                return True
            return False
        except IndexError:
            # No input is interpreted as 'do not overwrite'
            _LOGGER.warning('Skipping existing target file based on interactive user decision: %s', filepath)
            return False

    # If we get to this point, the file exists and we should overwrite it
    _LOGGER.warning('Overwriting existing target file because no action was specified otherwise: %s', filepath)
    return True


def process_single_file(stream_args, source, destination, interactive, no_overwrite, decode_input, encode_output, metadata_writer):
    # type: (STREAM_KWARGS, str, str, bool, bool, bool, bool, MetadataWriter) -> None
    """Processes a single encrypt/decrypt operation on a source file.

    :param dict stream_args: kwargs to pass to `aws_encryption_sdk.stream`
    :param str source: Full file path to source file
    :param str destination: Full file path to destination file
    :param bool interactive: Should prompt before overwriting existing files
    :param bool no_overwrite: Should never overwrite existing files
    :param bool decode_input: Should input be base64 decoded before operation
    :param bool encode_output: Should output be base64 encoded after operation
    :param metadata_writer: File-like to which metadata should be written
    :type metadata_writer: aws_encryption_sdk_cli.internal.metadata.MetadataWriter
    """
    if os.path.realpath(source) == os.path.realpath(destination):
        # File source, directory destination, empty suffix:
        _LOGGER.warning('Skipping because the source (%s) and destination (%s) are the same', source, destination)
        return

    _LOGGER.info('%sing file %s to %s', stream_args['mode'], source, destination)

    _stream_args = copy.copy(stream_args)
    # Because we can actually know size for files and Base64IO does not support seeking,
    # set the source length manually for files. This allows enables data key caching when
    # Base64-decoding a source file.
    source_file_size = os.path.getsize(source)
    if decode_input and not encode_output:
        _stream_args['source_length'] = int(source_file_size * (3 / 4))
    else:
        _stream_args['source_length'] = source_file_size

    with open(source, 'rb') as source_reader:
        process_single_operation(
            stream_args=_stream_args,
            source=source_reader,
            destination=destination,
            interactive=interactive,
            no_overwrite=no_overwrite,
            decode_input=decode_input,
            encode_output=encode_output,
            metadata_writer=metadata_writer
        )


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
        _LOGGER.debug('Using custom suffix "%s" to create target file', suffix)
    filename = source_filename.rsplit(os.sep, 1)[-1]
    _LOGGER.debug('Duplicating filename %s into %s', filename, destination_dir)
    return os.path.join(destination_dir, filename) + suffix


def _output_dir(source_root, destination_root, source_dir):
    # type: (str, str, str) -> str
    """Duplicates the source child directory structure into the target directory root.

    :param str source_root: Root of source directory
    :param str destination_root: Root of destination directory
    :param str source_dir: Actual directory of source file (child of source_root)
    """
    suffix = source_dir[len(source_root):].lstrip(os.path.sep)
    return os.path.join(destination_root, suffix)


def process_dir(stream_args, source, destination, interactive, no_overwrite, suffix, decode_input, encode_output, metadata_writer):
    # type: (STREAM_KWARGS, str, str, bool, bool, str, bool, bool, MetadataWriter) -> None
    """Processes encrypt/decrypt operations on all files in a directory tree.

    :param dict stream_args: kwargs to pass to `aws_encryption_sdk.stream`
    :param str source: Full file path to source directory root
    :param str destination: Full file path to destination directory root
    :param bool interactive: Should prompt before overwriting existing files
    :param bool no_overwrite: Should never overwrite existing files
    :param str suffix: Suffix to append to output filename
    :param bool decode_input: Should input be base64 decoded before operation
    :param bool encode_output: Should output be base64 encoded after operation
    :param metadata_writer: File-like to which metadata should be written
    :type metadata_writer: aws_encryption_sdk_cli.internal.metadata.MetadataWriter
    """
    _LOGGER.debug('%sing directory %s to %s', stream_args['mode'], source, destination)
    for base_dir, _dirs, files in os.walk(source):
        for filename in files:
            source_filename = os.path.join(base_dir, filename)
            destination_dir = _output_dir(
                source_root=source,
                destination_root=destination,
                source_dir=base_dir
            )
            destination_filename = output_filename(
                source_filename=source_filename,
                destination_dir=destination_dir,
                mode=str(stream_args['mode']),
                suffix=suffix
            )
            process_single_file(
                stream_args=stream_args,
                source=source_filename,
                destination=destination_filename,
                interactive=interactive,
                no_overwrite=no_overwrite,
                decode_input=decode_input,
                encode_output=encode_output,
                metadata_writer=metadata_writer
            )
