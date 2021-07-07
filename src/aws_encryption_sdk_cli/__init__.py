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
import sys
import traceback
import warnings
from argparse import Namespace  # noqa pylint: disable=unused-import

import aws_encryption_sdk
from aws_encryption_sdk.materials_managers import CommitmentPolicy
from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager  # noqa pylint: disable=unused-import

from aws_encryption_sdk_cli.exceptions import AWSEncryptionSDKCLIError, BadUserArgumentError
from aws_encryption_sdk_cli.internal.arg_parsing import CommitmentPolicyArgs, parse_args
from aws_encryption_sdk_cli.internal.identifiers import __version__  # noqa
from aws_encryption_sdk_cli.internal.io_handling import IOHandler, output_filename
from aws_encryption_sdk_cli.internal.logging_utils import LOGGER_NAME, setup_logger
from aws_encryption_sdk_cli.internal.master_key_parsing import build_crypto_materials_manager_from_args
from aws_encryption_sdk_cli.internal.metadata import MetadataWriter  # noqa pylint: disable=unused-import

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import List, Optional, Union  # noqa pylint: disable=unused-import

    from aws_encryption_sdk_cli.internal.mypy_types import STREAM_KWARGS  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

__all__ = ("cli", "process_cli_request", "stream_kwargs_from_args")
_LOGGER = logging.getLogger(LOGGER_NAME)


def _check_python_version():
    """Checks that we are on a supported version of Python.

    Emits a deprecation warning if we are on Python 2.
    """
    if sys.version_info.major < 3:
        warnings.warn(
            "Python 2 support will be removed in a future release. Please upgrade to Python 3.5 or higher.",
            DeprecationWarning,
        )


def _expand_sources(source):
    # type: (str) -> List[str]
    """Expands source using pathname patterns.
    https://docs.python.org/3/library/glob.html

    :param str source: Source pattern
    :returns: List of source paths
    :rtype: list
    """
    all_sources = glob.glob(source)
    if not all_sources:
        raise BadUserArgumentError("Invalid source.  Must be a valid pathname pattern or stdin (-)")
    _LOGGER.debug("Requested source: %s", source)
    _LOGGER.debug("Expanded source: %s", all_sources)
    return all_sources


def _catch_bad_destination_requests(destination):
    # type: (str) -> None
    """Catches bad requests based on characteristics of destination.

    :param str destination: Identifier for the destination (filesystem path or ``-`` for stdout)
    :raises BadUserArgument: if destination is a file in a directory that does not already exist
    """
    if destination != "-" and not os.path.isdir(destination):
        if not os.path.isdir(os.path.realpath(os.path.dirname(destination))):
            raise BadUserArgumentError("If destination is a file, the immediate parent directory must already exist.")


def _catch_bad_stdin_stdout_requests(source, destination):
    # type: (str, str) -> None
    """Catches bad requests based on characteristics of source and destination when
    source might be stdin or stdout.

    :param str source: Identifier for the source (filesystem path or ``-`` for stdin)
    :param str destination: Identifier for the destination (filesystem path or ``-`` for stdout)
    :raises BadUserArgument: if source and destination are the same
    :raises BadUserArgument: if source is stdin and destination is a directory
    """
    acting_as_pipe = destination == "-" and source == "-"
    if not acting_as_pipe and os.path.realpath(source) == os.path.realpath(destination):
        raise BadUserArgumentError("Destination and source cannot be the same")

    if source == "-" and os.path.isdir(destination):
        raise BadUserArgumentError("Destination may not be a directory when source is stdin")


def _catch_bad_file_and_directory_requests(expanded_sources, destination):
    # type: (List[str], str) -> None
    """Catches bad requests based on characteristics of source and destination when
    source contains files or directories.

    :param list expanded_sources: List of source paths
    :param str destination: Identifier for the destination (filesystem path or ``-`` for stdout)
    :raises BadUserArgumentError: if source contains multiple files and destination is not an existing directory
    :raises BadUserArgumentError: if source contains a directory and destination is not an existing directory
    """
    if len(expanded_sources) > 1 and not os.path.isdir(destination):
        raise BadUserArgumentError("If operating on multiple sources, destination must be an existing directory")

    for _source in expanded_sources:
        if os.path.isdir(_source):
            if not os.path.isdir(destination):
                raise BadUserArgumentError(
                    "If operating on a source directory, destination must be an existing directory"
                )


def _catch_bad_metadata_file_requests(metadata_output, source, destination):
    # type: (MetadataWriter, str, str) -> None
    """Catches bad requests based on characteristics of source, destination, and metadata
    output target.

    :raises BadUserArgumentError: if output file and metadata file are both ``stdout``
    :raises BadUserArgumentError: if metadata file would overwrite input file
    :raises BadUserArgumentError: if metadata file would overwrite output file
    :raises BadUserArgumentError: if metadata file is a directory
    :raises BadUserArgumentError: if input is a directory and contains metadata file
    :raises BadUserArgumentError: if output is a directory and contains metadata file
    :raises BadUserArgumentError: if metadata file value is empty
    """
    if metadata_output.suppress_output:
        return

    if not metadata_output.output_file:
        raise BadUserArgumentError("Metadata output file name cannot be empty")

    if metadata_output.output_file == "-":
        if destination == "-":
            raise BadUserArgumentError("Metadata output cannot be stdout when output is stdout")
        return

    real_source = os.path.realpath(source)
    real_destination = os.path.realpath(destination)
    real_metadata = os.path.realpath(metadata_output.output_file)

    if os.path.isdir(real_metadata):
        raise BadUserArgumentError("Metadata output cannot be a directory")

    if real_metadata in (real_source, real_destination):
        raise BadUserArgumentError("Metadata output file cannot be the input or output")

    if os.path.isdir(real_destination) and real_metadata.startswith(real_destination):
        raise BadUserArgumentError("Metadata output file cannot be in the output directory")

    if os.path.isdir(real_source) and real_metadata.startswith(real_source):
        raise BadUserArgumentError("Metadata output file cannot be in the input directory")


def process_cli_request(stream_args, parsed_args):  # noqa: C901
    # type: (STREAM_KWARGS, Namespace) -> None
    """Maps the operation request to the appropriate function based on the type of input and output provided.

    :param dict stream_args: kwargs to pass to `aws_encryption_sdk.stream`
    :param args: Parsed arguments from argparse
    :type args: argparse.Namespace
    """
    _catch_bad_destination_requests(parsed_args.output)
    _catch_bad_metadata_file_requests(
        metadata_output=parsed_args.metadata_output, source=parsed_args.input, destination=parsed_args.output
    )
    _catch_bad_stdin_stdout_requests(parsed_args.input, parsed_args.output)

    if not parsed_args.commitment_policy:
        commitment_policy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    elif parsed_args.commitment_policy == CommitmentPolicyArgs.FORBID_ENCRYPT_ALLOW_DECRYPT:
        commitment_policy = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT
    elif parsed_args.commitment_policy == CommitmentPolicyArgs.REQUIRE_ENCRYPT_ALLOW_DECRYPT:
        commitment_policy = CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT
    elif parsed_args.commitment_policy == CommitmentPolicyArgs.REQUIRE_ENCRYPT_REQUIRE_DECRYPT:
        commitment_policy = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    else:
        raise BadUserArgumentError("Invalid commitment policy.")

    handler = IOHandler(
        metadata_writer=parsed_args.metadata_output,
        interactive=parsed_args.interactive,
        no_overwrite=parsed_args.no_overwrite,
        decode_input=parsed_args.decode,
        encode_output=parsed_args.encode,
        required_encryption_context=parsed_args.encryption_context,
        required_encryption_context_keys=parsed_args.required_encryption_context_keys,
        commitment_policy=commitment_policy,
        buffer_output=parsed_args.buffer,
        max_encrypted_data_keys=parsed_args.max_encrypted_data_keys,
    )

    if parsed_args.input == "-":
        # read from stdin
        handler.process_single_operation(
            stream_args=stream_args, source=parsed_args.input, destination=parsed_args.output
        )
        return

    expanded_sources = _expand_sources(parsed_args.input)
    _catch_bad_file_and_directory_requests(expanded_sources, parsed_args.output)

    for _source in expanded_sources:
        _destination = copy.copy(parsed_args.output)

        if os.path.isdir(_source):
            if not parsed_args.recursive:
                _LOGGER.warning("Skipping %s because it is a directory and -r/-R/--recursive is not set", _source)
                continue

            handler.process_dir(
                stream_args=stream_args, source=_source, destination=_destination, suffix=parsed_args.suffix
            )

        elif os.path.isfile(_source):
            if os.path.isdir(parsed_args.output):
                # create new filename
                _destination = output_filename(
                    source_filename=_source,
                    destination_dir=_destination,
                    mode=str(stream_args["mode"]),
                    suffix=parsed_args.suffix,
                )
            # write to file
            handler.process_single_file(stream_args=stream_args, source=_source, destination=_destination)


def stream_kwargs_from_args(args, crypto_materials_manager):
    # type: (Namespace, CryptoMaterialsManager) -> STREAM_KWARGS
    """Builds kwargs object for aws_encryption_sdk.stream based on argparse
    arguments and existing CryptoMaterialsManager.

    :param args: Parsed arguments from argparse
    :type args: argparse.Namespace
    :param crypto_materials_manager: Existing CryptoMaterialsManager
    :type crypto_materials_manager: aws_encryption_sdk.materials_manager.base.CryptoMaterialsManager
    :returns: Translated kwargs object for aws_encryption_sdk.stream
    :rtype: dict
    """
    stream_args = {"materials_manager": crypto_materials_manager, "mode": args.action}
    # Look for additional arguments only if encrypting
    if args.action == "encrypt":
        stream_args["encryption_context"] = args.encryption_context
        if args.algorithm is not None:
            stream_args["algorithm"] = getattr(aws_encryption_sdk.Algorithm, args.algorithm)
        if args.frame_length is not None:
            stream_args["frame_length"] = args.frame_length

    if args.commitment_policy is None:
        stream_args["commitment_policy"] = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    elif args.commitment_policy == "require-encrypt-require-decrypt":
        stream_args["commitment_policy"] = CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT
    elif args.commitment_policy == "require-encrypt-allow-decrypt":
        stream_args["commitment_policy"] = CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT
    elif args.commitment_policy == "forbid-encrypt-allow-decrypt":
        stream_args["commitment_policy"] = CommitmentPolicy.FORBID_ENCRYPT_ALLOW_DECRYPT

    if args.max_length is not None:
        stream_args["max_body_length"] = args.max_length
    return stream_args


def cli(raw_args=None):
    # type: (List[str]) -> Union[str, None]
    """CLI entry point.  Processes arguments, sets up the key provider, and processes requested action.

    :returns: Execution return value intended for ``sys.exit()``
    """
    try:
        args = parse_args(raw_args)

        setup_logger(args.verbosity, args.quiet)  # pylint: disable=no-member

        _LOGGER.debug("Encryption mode: %s", args.action)  # pylint: disable=no-member
        _LOGGER.debug("Encryption source: %s", args.input)  # pylint: disable=no-member
        _LOGGER.debug("Encryption destination: %s", args.output)  # pylint: disable=no-member
        _LOGGER.debug("Wrapping key provider configuration: %s", args.wrapping_keys)  # pylint: disable=no-member
        _LOGGER.debug("Suffix requested: %s", args.suffix)  # pylint: disable=no-member

        _check_python_version()

        crypto_materials_manager = build_crypto_materials_manager_from_args(
            key_providers_config=args.wrapping_keys, caching_config=args.caching
        )

        stream_args = stream_kwargs_from_args(args, crypto_materials_manager)

        process_cli_request(stream_args, args)

        return None
    except AWSEncryptionSDKCLIError as error:
        return error.args[0]
    except Exception as error:  # pylint: disable=broad-except
        message = os.linesep.join(
            [
                "Encountered unexpected error: increase verbosity to see details.",
                "{cls}({args})".format(
                    cls=error.__class__.__name__, args=", ".join(['"{}"'.format(arg) for arg in error.args])
                ),
            ]
        )
        _LOGGER.debug(message)
        # copy.deepcopy can't handle raw exc_info objects, so format it first
        formatted_traceback = traceback.format_exc()
        _LOGGER.debug(formatted_traceback)
        return message
