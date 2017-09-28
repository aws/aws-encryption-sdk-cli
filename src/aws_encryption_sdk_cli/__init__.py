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
"""AWS Encryption SDK CLI."""
import copy
import glob
import logging
import os

import aws_encryption_sdk

from aws_encryption_sdk_cli.exceptions import BadUserArgumentError
from aws_encryption_sdk_cli.internal.arg_parsing import parse_args
# convenience import separated from other imports from this module to avoid over-application of linting override
from aws_encryption_sdk_cli.internal.identifiers import __version__  # noqa
from aws_encryption_sdk_cli.internal.identifiers import LOGGER_NAME, LOGGING_LEVELS, MAX_LOGGING_LEVEL
from aws_encryption_sdk_cli.internal.io_handling import (
    output_filename, process_dir, process_single_file, process_single_operation
)
from aws_encryption_sdk_cli.internal.master_key_parsing import build_crypto_materials_manager_from_args

_LOGGER = logging.getLogger(LOGGER_NAME)


def _expand_sources(source):
    """Expands source using pathname patterns.
    https://docs.python.org/3/library/glob.html

    :param str source: Source pattern
    :returns: List of source paths
    :rtype: list
    """
    all_sources = glob.iglob(source)
    if not all_sources:
        raise BadUserArgumentError('Invalid source.  Must be a valid pathname pattern or stdin (-)')
    _LOGGER.debug('Requested source: %s', source)
    _LOGGER.debug('Expanded source: %s', all_sources)
    return all_sources


def process_cli_request(stream_args, source, destination, recursive, interactive, no_overwrite):
    """Maps the operation request to the appropriate function based on the type of input and output provided.

    :param dict stream_args: kwargs to pass to `aws_encryption_sdk.stream`
    :param str source: Identifier for the source (filesystem path or ``-`` for stdin)
    :param str destination: Identifier for the destination (filesystem path or ``-`` for stdout)
    :param bool recursive: Should recurse over directories
    :param bool interactive: Should prompt before overwriting existing files
    :param bool no_overwrite: Should never overwrite existing files
    :raises BadUserArgumentError: if called with source directory and not specified as recursive
    :raises BadUserArgumentError: if called with a source directory and a destination that is anything
    other than a directory
    :raises BadUserArgumentError: if called with an unknown type of source
    """
    acting_as_pipe = destination == '-' and source == '-'
    if destination == source and not acting_as_pipe:
        raise BadUserArgumentError('Destination and source cannot be the same')
    dest_is_dir = os.path.isdir(destination)

    if source == '-':
        if dest_is_dir:
            raise BadUserArgumentError('Destination may not be a directory when source is stdin')
        # read from stdin
        process_single_operation(
            stream_args=stream_args,
            source=source,
            destination=destination,
            interactive=interactive,
            no_overwrite=no_overwrite
        )
        return

    for _source in _expand_sources(source):
        _destination = copy.copy(destination)

        if os.path.isdir(_source):
            if not recursive:
                raise BadUserArgumentError('Must specify -r/-R/--recursive when operating on a source directory')
            if not dest_is_dir:
                raise BadUserArgumentError(
                    'If operating on a source directory, destination must be an existing directory'
                )
            process_dir(
                stream_args=stream_args,
                source=_source,
                destination=_destination,
                interactive=interactive,
                no_overwrite=no_overwrite
            )

        elif os.path.isfile(_source):
            if dest_is_dir:
                # create new filename
                _destination = output_filename(
                    source_filename=_source,
                    destination_dir=_destination,
                    mode=stream_args['mode']
                )
            # write to file
            process_single_file(
                stream_args=stream_args,
                source=_source,
                destination=_destination,
                interactive=interactive,
                no_overwrite=no_overwrite
            )


def stream_kwargs_from_args(args, crypto_materials_manager):
    """Builds kwargs object for aws_encryption_sdk.stream based on argparse
    arguments and existing CryptoMaterialsManager.

    :param args: Parsed arguments from argparse
    :param crypto_materials_manager: Existing CryptoMaterialsManager
    :type crypto_materials_manager: aws_encryption_sdk.materials_manager.base.CryptoMaterialsManager
    :returns: Translated kwargs object for aws_encryption_sdk.stream
    :rtype: dict
    """
    stream_args = {
        'materials_manager': crypto_materials_manager,
        'mode': args.action
    }
    # Look for additional arguments only if encrypting
    if args.action == 'encrypt':
        if args.encryption_context is not None:
            stream_args['encryption_context'] = args.encryption_context
        if args.algorithm is not None:
            stream_args['algorithm'] = getattr(aws_encryption_sdk.Algorithm, args.algorithm)
        if args.frame_length is not None:
            stream_args['frame_length'] = args.frame_length

    if args.max_length is not None:
        stream_args['max_body_length'] = args.max_length
    return stream_args


def cli(raw_args=None):
    """CLI entry point.  Processes arguments, sets up the key provider, and processes requested action.

    :returns: Execution return value intended for ``sys.exit()``
    """
    args = parse_args(raw_args)

    logging_args = {}
    if args.verbosity is not None and args.verbosity > 0:
        logging_args['level'] = LOGGING_LEVELS[min(args.verbosity, MAX_LOGGING_LEVEL)]
    logging.basicConfig(**logging_args)

    _LOGGER.debug('Encryption mode: %s', args.action)
    _LOGGER.debug('Encryption source: %s', args.input)
    _LOGGER.debug('Encryption destination: %s', args.output)
    _LOGGER.debug('Master key provider configuration: %s', args.master_keys)

    crypto_materials_manager = build_crypto_materials_manager_from_args(
        key_providers_config=args.master_keys,
        caching_config=args.caching
    )

    stream_args = stream_kwargs_from_args(args, crypto_materials_manager)

    try:
        return process_cli_request(
            stream_args=stream_args,
            source=args.input,
            destination=args.output,
            recursive=args.recursive,
            interactive=args.interactive,
            no_overwrite=args.no_overwrite
        )
    except BadUserArgumentError as error:
        return error.args[0]
