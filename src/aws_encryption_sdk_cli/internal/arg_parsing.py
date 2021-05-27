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
"""Helper functions for parsing and processing input arguments."""
import argparse
import copy
import logging
import os
import platform
import shlex
from collections import OrderedDict, defaultdict
from enum import Enum

import aws_encryption_sdk
import six

from aws_encryption_sdk_cli.exceptions import ParameterParseError
from aws_encryption_sdk_cli.internal.identifiers import ALGORITHM_NAMES, DEFAULT_MASTER_KEY_PROVIDER, __version__
from aws_encryption_sdk_cli.internal.logging_utils import LOGGER_NAME
from aws_encryption_sdk_cli.internal.metadata import MetadataWriter

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Any, Dict, List, Optional, Sequence, Tuple, Union  # noqa pylint: disable=unused-import

    from aws_encryption_sdk_cli.internal.mypy_types import (  # noqa pylint: disable=unused-import
        ARGPARSE_TEXT,
        CACHING_CONFIG,
        COLLAPSED_CONFIG,
        MASTER_KEY_PROVIDER_CONFIG,
        PARSED_CONFIG,
        RAW_CONFIG,
    )
except ImportError:  # pragma: no cover
    cast = lambda typ, val: val  # noqa pylint: disable=invalid-name
    # We only actually need the other imports when running the mypy checks

__all__ = ("parse_args",)
_LOGGER = logging.getLogger(LOGGER_NAME)


class CommentIgnoringArgumentParser(argparse.ArgumentParser):
    """``ArgumentParser`` that ignores lines in ``fromfile_prefix_chars`` files which start with ``#``."""

    def __init__(self, *args, **kwargs):
        """Sets up the dummy argument registry."""
        # The type profile for this it really complex and we don't do anything to it, so
        # I would rather not duplicate the typeshed's effort keeping it up to date.
        # https://github.com/python/typeshed/blob/master/stdlib/2and3/argparse.pyi#L27-L39
        self.__dummy_arguments = []
        self.__is_windows = any(platform.win32_ver())
        super(CommentIgnoringArgumentParser, self).__init__(*args, **kwargs)

    def add_dummy_redirect_argument(self, expected_name):
        # type: (argparse.ArgumentParser, str) -> None
        """Adds a dummy redirect argument to the provided parser to catch typos when calling
        the specified valid long-form name.

        :param parser: Parser to which to add argument
        :type parser: argparse.ArgumentParser
        :param str expected_name: Valid long-form name for which to add dummy redirect
        """
        self.add_argument(
            expected_name[1:],
            dest="dummy_redirect",
            action="store_const",
            const=expected_name[1:],
            help=argparse.SUPPRESS,
        )
        # ArgumentParser subclass confuses mypy
        self.__dummy_arguments.append(expected_name[1:])  # type: ignore

    def add_argument(self, *args, **kwargs):
        # The type profile for this it really complex and we don't do anything substantive
        # to it, so I would rather not duplicate the typeshed's effort keeping it up to date.
        # https://github.com/python/typeshed/blob/master/stdlib/2and3/argparse.pyi#L53-L65
        """Adds the requested argument to the parser, also adding a dummy redirect argument
        if a long-form argument (starts with two starting prefix characters) is found.

        See: https://docs.python.org/dev/library/argparse.html#the-add-argument-method
        """
        for long_arg in [arg for arg in args if arg.startswith(self.prefix_chars * 2)]:
            self.add_dummy_redirect_argument(long_arg)

        return super(CommentIgnoringArgumentParser, self).add_argument(*args, **kwargs)

    def __parse_line(self, arg_line):
        # type: (ARGPARSE_TEXT) -> List[str]
        """Parses a line of arguments into individual arguments intelligently for different platforms.
        This differs from standard shlex behavior in that is supports escaping both single and double
        quotes and on Windows platforms uses the Windows-native escape character "`".

        :param str arg_line: Raw argument line
        :returns: Parsed line members
        :rtype: list of str
        """
        shlexer = shlex.shlex(six.StringIO(arg_line), posix=True)  # type: ignore #  shlex confuses mypy
        shlexer.whitespace_split = True
        shlexer.escapedquotes = "'\""
        if self.__is_windows:
            shlexer.escape = "`"
        return list(shlexer)  # type: ignore #  shlex confuses mypy

    def convert_arg_line_to_args(self, arg_line):
        # type: (ARGPARSE_TEXT) -> List[str]
        """Converts a line of arguments into individual arguments, expanding user and environment variables.

        :param str arg_line: Raw argument line
        :returns: Converted line members
        :rtype: list of str
        """
        converted_line = []
        for arg in self.__parse_line(arg_line):
            arg = arg.strip()
            user_arg = os.path.expanduser(arg)
            environ_arg = os.path.expandvars(user_arg)
            converted_line.append(environ_arg)
        return converted_line


class UniqueStoreAction(argparse.Action):  # pylint: disable=too-few-public-methods
    """argparse action that requires that arguments cannot be repeated."""

    def __call__(
        self,
        parser,  # type: argparse.ArgumentParser
        namespace,  # type: argparse.Namespace
        values,  # type: Union[ARGPARSE_TEXT, Sequence[Any], None]
        option_string=None,  # type: Optional[ARGPARSE_TEXT]
    ):
        # type: (...) -> None
        """Checks to make sure that the destination is empty before writing.

        :raises parser.error: if destination is already set
        """
        if getattr(namespace, self.dest) is not None:  # type: ignore # typeshed doesn't know about Action.dest yet?
            parser.error("{} argument may not be specified more than once".format(option_string))
            return
        setattr(namespace, self.dest, values)  # type: ignore # typeshed doesn't know about Action.dest yet?


def _version_report():
    # type: () -> str
    """Returns a formatted report of the versions of this CLI and relevant dependencies.

    :rtype: str
    """
    versions = OrderedDict()  # type: Dict[str, str]
    versions["aws-encryption-sdk-cli"] = __version__
    versions["aws-encryption-sdk"] = aws_encryption_sdk.__version__
    return " ".join(
        ["{target}/{version}".format(target=target, version=version) for target, version in versions.items()]
    )


def _build_parser():
    # type: () -> CommentIgnoringArgumentParser
    """Builds the argument parser.

    :returns: Constructed argument parser
    :rtype: argparse.ArgumentParser
    """
    parser = CommentIgnoringArgumentParser(
        description="Encrypt or decrypt data using the AWS Encryption SDK",
        epilog="For more usage instructions and examples, see: http://aws-encryption-sdk-cli.readthedocs.io/en/latest/",
        fromfile_prefix_chars="@",
    )

    # For each argument added to this group, a dummy redirect argument must
    # be added to the parent parser for each long form option string.
    version_or_action = parser.add_mutually_exclusive_group(required=True)

    version_or_action.add_argument("--version", action="version", version=_version_report())
    parser.add_dummy_redirect_argument("--version")

    # For each argument added to this group, a dummy redirect argument must
    # be added to the parent parser for each long form option string.
    operating_action = version_or_action.add_mutually_exclusive_group()
    operating_action.add_argument(
        "-e", "--encrypt", dest="action", action="store_const", const="encrypt", help="Encrypt data"
    )
    parser.add_dummy_redirect_argument("--encrypt")
    operating_action.add_argument(
        "-d", "--decrypt", dest="action", action="store_const", const="decrypt", help="Decrypt data"
    )
    parser.add_dummy_redirect_argument("--decrypt")
    operating_action.add_argument(
        "--decrypt-unsigned",
        dest="action",
        action="store_const",
        const="decrypt-unsigned",
        help="Decrypt data and enforce messages are unsigned during decryption.",
    )
    parser.add_dummy_redirect_argument("--decrypt-unsigned")

    # For each argument added to this group, a dummy redirect argument must
    # be added to the parent parser for each long form option string.
    metadata_group = parser.add_mutually_exclusive_group(required=True)

    metadata_group.add_argument(
        "-S",
        "--suppress-metadata",
        action="store_const",
        const=MetadataWriter(suppress_output=True)(),
        dest="metadata_output",
        help="Suppress metadata output.",
    )
    parser.add_dummy_redirect_argument("--suppress-metadata")

    metadata_group.add_argument(
        "--metadata-output", type=MetadataWriter(), help="File to which to write metadata records"
    )
    parser.add_dummy_redirect_argument("--metadata-output")

    parser.add_argument(
        "--overwrite-metadata",
        action="store_true",
        help="Force metadata output to overwrite contents of file rather than appending to file",
    )

    parser.add_argument(
        "-w",
        "--wrapping-keys",
        nargs="+",
        dest="wrapping_keys",
        action="append",
        required=True,
        help=(
            "Identifying information for a wrapping key provider and wrapping keys. Each instance must include "
            "a wrapping key provider identifier and identifiers for one or more wrapping key supplied by that "
            " provider. ex: "
            "--wrapping-keys provider=aws-kms key=$AWS_KMS_KEY_ARN"
        ),
    )

    parser.add_argument(
        "--commitment-policy",
        type=CommitmentPolicyArgs,
        choices=list(CommitmentPolicyArgs),
        default=CommitmentPolicyArgs.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        help=(
            "Specifies the commitment policy for key commitment. "
            "ex: "
            "--commitment-policy=forbid-encrypt-allow-decrypt"
        ),
    )

    parser.add_argument(
        "--caching",
        nargs="+",
        required=False,
        action=UniqueStoreAction,
        help=(
            "Configuration options for a caching cryptographic materials manager and local cryptographic materials "
            'cache. Must consist of "key=value" pairs. If caching, at least "capacity" and "max_age" must be defined. '
            "ex: "
            "--caching capacity=10 max_age=100.0"
        ),
    )

    parser.add_argument(
        "-b", "--buffer", action="store_true", help="Buffer result in memory before releasing to output"
    )

    parser.add_argument(
        "-i",
        "--input",
        required=True,
        action=UniqueStoreAction,
        help='Input file or directory for encrypt/decrypt operation, or "-" for stdin.',
    )
    parser.add_argument(
        "-o",
        "--output",
        required=True,
        action=UniqueStoreAction,
        help="Output file or directory for encrypt/decrypt operation, or - for stdout.",
    )

    parser.add_argument("--encode", action="store_true", help="Base64-encode output after processing")
    parser.add_argument("--decode", action="store_true", help="Base64-decode input before processing")

    parser.add_argument(
        "-c",
        "--encryption-context",
        nargs="+",
        action=UniqueStoreAction,
        help=(
            'key-value pair encryption context values (encryption only). Must a set of "key=value" pairs. '
            "ex: "
            "-c key1=value1 key2=value2"
        ),
    )

    # Note: This is added as an argument for argparse API consistency, but it should not be used directly.
    parser.add_argument(
        "--required-encryption-context-keys", nargs="+", action=UniqueStoreAction, help=argparse.SUPPRESS
    )

    parser.add_argument(
        "--algorithm", action=UniqueStoreAction, help="Algorithm name (encryption only)", choices=ALGORITHM_NAMES
    )

    parser.add_argument(
        "--frame-length",
        dest="frame_length",
        type=int,
        action=UniqueStoreAction,
        help="Frame length in bytes (encryption only)",
    )

    parser.add_argument(
        "--max-length",
        type=int,
        action=UniqueStoreAction,
        help=(
            "Maximum frame length (for framed messages) or content length (for "
            "non-framed messages) (decryption only)"
        ),
    )

    parser.add_argument(
        "--max-encrypted-data-keys",
        type=int,
        action=UniqueStoreAction,
        help="Maximum number of encrypted data keys to wrap (during encryption) or to unwrap (during decryption)",
    )

    parser.add_argument(
        "--suffix",
        nargs="?",
        const="",
        action=UniqueStoreAction,
        help="Custom suffix to use when target filename is not specified (empty if specified but no value provided)",
    )

    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Force aws-encryption-cli to prompt you for verification before overwriting existing files",
    )

    parser.add_argument("--no-overwrite", action="store_true", help="Never overwrite existing files")

    parser.add_argument("-r", "-R", "--recursive", action="store_true", help="Allow operation on directories as input")

    parser.add_argument(
        "-v",
        dest="verbosity",
        action="count",
        help="Enables logging and sets detail level. Multiple -v options increases verbosity (max: 4).",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppresses most warning and diagnostic messages")
    return parser


def _parse_kwargs(args):
    # type: (RAW_CONFIG) -> PARSED_CONFIG
    """Parses a list of CLI arguments of "key=value" form into key/values pairs.

    :param iterable args: arguments to unpack
    :returns: parsed arguments
    :rtype: dict
    :raises ParameterParseError: if a badly formed parameter if found
    """
    value_error_message = 'Argument parameter must follow the format "key=value"'
    kwargs = defaultdict(list)  # type: Dict[str, List[str]]
    for arg in args:
        _LOGGER.debug("Attempting to parse argument: %s", arg)
        try:
            key, value = arg.split("=", 1)
            if not (key and value):
                raise ParameterParseError(value_error_message)
            kwargs[key].append(value)
        except ValueError:
            _LOGGER.debug("Failed to parse argument")
            raise ParameterParseError(value_error_message)
    return dict(kwargs)


def _collapse_config(config):
    # type: (PARSED_CONFIG) -> COLLAPSED_CONFIG
    """Collapses a dict returned by ``_parse_kwargs``, replacing each value list with its first entry.

    :param dict config: Configuration to collapse
    :returns: Collapsed configuration
    :rtype: dict
    """
    config = copy.deepcopy(config)
    collapsed_config = {}  # type: Dict[str, str]
    for key in config:
        collapsed_config[key] = config[key][0]
    return collapsed_config


def _parse_and_collapse_config(raw_config):
    # type: (RAW_CONFIG) -> COLLAPSED_CONFIG
    """Copies, parses, and collapses a raw configuration of "key=value" pairs.

    :param list raw_config: Unprocessed key=value configuration
    :returns: Processed configuration
    :rtype: dict
    """
    config = copy.deepcopy(raw_config)
    parsed_config = _parse_kwargs(config)
    collapsed_config = _collapse_config(parsed_config)
    return collapsed_config


def _process_encryption_context(
    action, raw_encryption_context, raw_required_encryption_context_keys
):  # pylint: disable=invalid-name
    # type: (str, RAW_CONFIG, RAW_CONFIG) -> Tuple[Dict[str, str], List[str]]
    """Applies processing to prepare the encryption context and required encryption context keys.

    :param list raw_encryption_context: Unprocessed encryption context
    :param list raw_required_encryption_context_keys: Unprocessed required encryption context keys
    :returns: Processed encryption context and required encryption context keys
    :rtype: tuple of dict and list
    """
    if raw_required_encryption_context_keys is not None:
        required_keys = copy.copy(raw_required_encryption_context_keys)
    else:
        required_keys = []

    if raw_encryption_context is None:
        return {}, required_keys

    if action == "encrypt":
        return _parse_and_collapse_config(raw_encryption_context), required_keys

    initial_encryption_context = []  # type: List[str]
    for param in raw_encryption_context:
        if "=" in param:
            initial_encryption_context.append(param)
        else:
            required_keys.append(param)
    encryption_context = _parse_and_collapse_config(initial_encryption_context)
    return encryption_context, required_keys


def _process_caching_config(raw_caching_config):
    # type: (RAW_CONFIG) -> CACHING_CONFIG
    """Applies additional processing to prepare the caching configuration.

    :param list raw_caching_config: Unprocessed caching configuration
    :returns: Processed caching configuration
    :rtype: dict
    :raises ParameterParseError: if invalid parameter name is found
    :raises ParameterParseError: if either capacity or max_age are not defined
    """
    _cast_types = {"capacity": int, "max_messages_encrypted": int, "max_bytes_encrypted": int, "max_age": float}
    parsed_config = _parse_and_collapse_config(raw_caching_config)

    if "capacity" not in parsed_config or "max_age" not in parsed_config:
        raise ParameterParseError('If enabling caching, both "capacity" and "max_age" are required')

    caching_config = {}  # type: Dict[str, Union[str, int, float]]
    for key, value in parsed_config.items():
        try:
            caching_config[key] = _cast_types[key](value)
        except KeyError:
            raise ParameterParseError('Invalid caching configuration key: "{}"'.format(key))
    return caching_config


def _process_non_kms_key_config(parsed_args):
    """Processes a single key provider configuration for a non-KMS wrapping key

    :param dict parsed_args: The parsed kwargs for the key provider
    """
    if "discovery" in parsed_args or "discovery-account" in parsed_args or "discovery-partition" in parsed_args:
        raise ParameterParseError("Discovery attributes are supported only for AWS KMS wrapping keys")

    if "key" not in parsed_args:
        raise ParameterParseError('At least one "key" must be provided for each wrapping key provider configuration')

    return parsed_args


def _process_kms_key_config(parsed_args, action):
    """Processes a single key provider configuration for a KMS wrapping key

    :param dict parsed_args: The parsed kwargs for the key provider
    :param action: The action being taken (encrypt or decrypt)
    """
    args_include_discovery = (
        "discovery" in parsed_args or "discovery-account" in parsed_args or "discovery-partition" in parsed_args
    )

    if action == "encrypt" and args_include_discovery:
        raise ParameterParseError("Discovery attributes are supported only on decryption for AWS KMS keys")

    if "key" not in parsed_args and action == "encrypt":
        raise ParameterParseError('At least one "key" must be provided for each wrapping key provider configuration')

    _process_discovery_args(parsed_args)

    discovery = parsed_args["discovery"]
    if "key" in parsed_args and discovery:
        # Decrypt MUST fail without attempting any decryption if discovery mode is enabled
        # and at least one key=<Key ARN> parameter value is provided
        raise ParameterParseError("If discovery is true (enabled), you cannot specify wrapping keys")
    if "key" not in parsed_args:
        if not discovery:
            # Decrypt MUST fail without attempting any decryption if discovery mode is disabled
            # and no key=<Key ARN> parameter value is provided
            raise ParameterParseError("When discovery is false (disabled), you must specify at least one wrapping key")
        parsed_args["key"] = []
    return parsed_args


def _process_wrapping_key_provider_configs(  # noqa: C901
    raw_keys,  # type: List[RAW_CONFIG]
    action,  # type: str
):
    # type: (...) -> List[MASTER_KEY_PROVIDER_CONFIG]
    """Applied additional processing to prepare the wrapping key provider configuration.

    :param list raw_keys: List of wrapping key provider configurations
    :param str action: Action defined in CLI input
    :returns: List of processed wrapping key provider configurations
    :rtype: list of dicts
    :raises ParameterParseError: if exactly one provider value is not provided
    :raises ParameterParseError: if no key values are provided
    """
    if raw_keys is None:
        raise ParameterParseError("No wrapping key provider configuration found")

    processed_configs = []  # type: List[MASTER_KEY_PROVIDER_CONFIG]
    for raw_config in raw_keys:
        parsed_args = {}  # type: Dict[str, Union[str, List[str], Dict[str, Union[str, List[str]]]]]
        parsed_args.update(_parse_kwargs(raw_config))

        provider = parsed_args.get("provider", [DEFAULT_MASTER_KEY_PROVIDER])  # If no provider is defined, use aws-kms
        if len(provider) != 1:
            raise ParameterParseError(
                'You must provide exactly one "provider" for each wrapping key provider configuration. '
                "{} provided".format(len(provider))
            )
        parsed_args["provider"] = provider[0]  # type: ignore

        provider_is_kms = parsed_args["provider"] in ("aws-kms", DEFAULT_MASTER_KEY_PROVIDER)

        if not provider_is_kms:
            processed_configs.append(_process_non_kms_key_config(parsed_args))
        else:
            processed_configs.append(_process_kms_key_config(parsed_args, action))  # type: ignore
    return processed_configs


def _process_discovery_args(key_config):  # noqa: C901
    """Process rules for discovery filters on Account ID and Partition ID
    :param key_config: The key configuration being parsed
    :raises: ParameterParseError
    """
    if "discovery" not in key_config:
        if "discovery-account" in key_config or "discovery-partition" in key_config:
            raise ParameterParseError(
                "Discovery-account and discovery-partition are valid only when the discovery attribute is set to true"
            )

        key_config["discovery"] = False
        return

    # Translate the raw value of 'discovery' as passed by customer into a bool we can work with
    discovery = discovery_pseudobool(key_config.pop("discovery")[0])
    key_config["discovery"] = discovery

    accounts = key_config.get("discovery-account", None)
    partition = key_config.get("discovery-partition", None)

    if not discovery:
        if accounts or partition:
            raise ParameterParseError(
                "Discovery-account and discovery-partition are valid only when the discovery attribute is set to true"
            )
    else:
        if accounts and not partition:
            raise ParameterParseError("When specifying discovery-account, you must also specify discovery-partition")
        if partition and not accounts:
            raise ParameterParseError("When specifying discovery-partition, you must also specify discovery-account")

        if accounts and partition:
            for account in accounts:
                if len(account) == 0:
                    raise ParameterParseError("Value passed to discovery-account cannot be empty")
            if len(partition) != 1:
                raise ParameterParseError("You can only specify discovery-partition once")
            if not partition[0]:
                raise ParameterParseError("Value passed to discovery-partition cannot be empty")

            key_config["discovery-partition"] = partition[0]


def discovery_pseudobool(value):
    """Translates an input value in various 'truthy' or 'falsy' forms into a boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value.lower() in {"false", "f", "0", "no", "n"}:
            return False
        if value.lower() in {"true", "t", "1", "yes", "y"}:
            return True
    raise ParameterParseError("Value {} could not be parsed as true or false".format(value))


class CommitmentPolicyArgs(Enum):
    """Defines the possible values for a commitment policy"""

    FORBID_ENCRYPT_ALLOW_DECRYPT = "forbid-encrypt-allow-decrypt"
    REQUIRE_ENCRYPT_ALLOW_DECRYPT = "require-encrypt-allow-decrypt"
    REQUIRE_ENCRYPT_REQUIRE_DECRYPT = "require-encrypt-require-decrypt"

    def str(self):
        """Returns the string value for the commitment policy"""
        return self.value


def parse_args(raw_args=None):
    # type: (Optional[List[str]]) -> argparse.Namespace
    """Handles argparse to collect the needed input values.

    :param list raw_args: List of arguments
    :returns: parsed arguments
    :rtype: argparse.Namespace
    """
    parser = _build_parser()
    parsed_args = parser.parse_args(args=raw_args)

    try:
        if parsed_args.dummy_redirect is not None:
            raise ParameterParseError(
                'Found invalid argument "{actual}". Did you mean "-{actual}"?'.format(actual=parsed_args.dummy_redirect)
            )

        # We add the 'required_encryption_context_keys' to arg parse, even though it is not
        # meant to be used by customers, so that we can  pass the parsed arguments around internally
        if parsed_args.required_encryption_context_keys is not None:
            raise ParameterParseError("--required-encryption-context-keys cannot be manually provided")

        if parsed_args.overwrite_metadata:
            parsed_args.metadata_output.force_overwrite()

        parsed_args.wrapping_keys = _process_wrapping_key_provider_configs(
            parsed_args.wrapping_keys, parsed_args.action
        )

        # mypy does not appear to understand nargs="+" behavior
        parsed_args.encryption_context, parsed_args.required_encryption_context_keys = _process_encryption_context(
            action=parsed_args.action,
            raw_encryption_context=parsed_args.encryption_context,
            raw_required_encryption_context_keys=parsed_args.required_encryption_context_keys,  # type: ignore
        )

        if parsed_args.caching is not None:
            parsed_args.caching = _process_caching_config(parsed_args.caching)
    except ParameterParseError as error:
        parser.error(*error.args)

    return parsed_args
