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
from collections import defaultdict, OrderedDict
import copy
import logging
import shlex
from typing import Any, Dict, List, Optional, Sequence, Union  # noqa pylint: disable=unused-import

import aws_encryption_sdk

from aws_encryption_sdk_cli.exceptions import ParameterParseError
from aws_encryption_sdk_cli.internal.identifiers import __version__, ALGORITHM_NAMES
from aws_encryption_sdk_cli.internal.logging_utils import LOGGER_NAME
from aws_encryption_sdk_cli.internal.mypy_types import (  # noqa pylint: disable=unused-import
    ARGPARSE_TEXT, CACHING_CONFIG, COLLAPSED_CONFIG,
    MASTER_KEY_PROVIDER_CONFIG, PARSED_CONFIG, RAW_CONFIG
)

_LOGGER = logging.getLogger(LOGGER_NAME)


class CommentIgnoringArgumentParser(argparse.ArgumentParser):
    """``ArgumentParser`` that ignores lines in ``fromfile_prefix_chars`` files which start with ``#``."""

    def convert_arg_line_to_args(self, arg_line):
        # type: (ARGPARSE_TEXT) -> List[str]
        """Applies whitespace stripping to individual arguments in each line and
        drops both full-line and in-line comments.
        """
        converted_line = []
        for arg in shlex.split(str(arg_line)):
            arg = arg.strip()
            if arg.startswith('#'):
                break
            converted_line.append(arg)
        return converted_line


class UniqueStoreAction(argparse.Action):  # pylint: disable=too-few-public-methods
    """argparse action that requires that arguments cannot be repeated."""

    def __call__(
            self,
            parser,  # type: argparse.ArgumentParser
            namespace,  # type: argparse.Namespace
            values,  # type: Union[ARGPARSE_TEXT, Sequence[Any], None]
            option_string=None  # type: Optional[ARGPARSE_TEXT]
    ):
        # type: (...) -> None
        """Checks to make sure that the destination is empty before writing.

        :raises parser.error: if destination is already set
        """
        if getattr(namespace, self.dest) is not None:  # type: ignore # typeshed doesn't know about Action.dest yet?
            parser.error('{} argument may not be specified more than once'.format(option_string))
            return
        setattr(namespace, self.dest, values)  # type: ignore # typeshed doesn't know about Action.dest yet?


def _version_report():
    # type: () -> str
    """Returns a formatted report of the versions of this CLI and relevant dependencies.

    :rtype: str
    """
    versions = OrderedDict()  # type: Dict[str, str]
    versions['aws-encryption-sdk-cli'] = __version__
    versions['aws-encryption-sdk'] = aws_encryption_sdk.__version__
    return ' '.join([
        '{target}/{version}'.format(target=target, version=version)
        for target, version
        in versions.items()
    ])


def _build_parser():
    # type: () -> CommentIgnoringArgumentParser
    """Builds the argument parser.

    :returns: Constructed argument parser
    :rtype: argparse.ArgumentParser
    """
    parser = CommentIgnoringArgumentParser(
        description='Encrypt or decrypt data using the AWS Encryption SDK',
        epilog='For more usage instructions and examples, see: http://aws-encryption-sdk-cli.readthedocs.io/en/latest/',
        fromfile_prefix_chars='@'
    )

    version_or_action = parser.add_mutually_exclusive_group(required=True)

    version_or_action.add_argument(
        '--version',
        action='version',
        version=_version_report()
    )

    operating_action = version_or_action.add_mutually_exclusive_group()
    operating_action.add_argument(
        '-e',
        '--encrypt',
        dest='action',
        action='store_const',
        const='encrypt',
        help='Encrypt data'
    )
    operating_action.add_argument(
        '-d',
        '--decrypt',
        dest='action',
        action='store_const',
        const='decrypt',
        help='Decrypt data'
    )

    parser.add_argument(
        '-m',
        '--master-keys',
        nargs='+',
        action='append',
        required=False,
        help=(
            'Identifying information for a master key provider and master keys. Each instance must include '
            'a master key provider identifier and identifiers for one or more master key supplied by that provider. '
            'ex: '
            '--master-keys provider=aws-kms key=$AWS_KMS_KEY_ARN'
        )
    )

    parser.add_argument(
        '--caching',
        nargs='+',
        required=False,
        action=UniqueStoreAction,
        help=(
            'Configuration options for a caching cryptographic materials manager and local cryptographic materials '
            'cache. Must consist of "key=value" pairs. If caching, at least "capacity" and "max_age" must be defined. '
            'ex: '
            '--caching capacity=10 max_age=100.0'
        )
    )

    parser.add_argument(
        '-i',
        '--input',
        required=True,
        action=UniqueStoreAction,
        help='Input file or directory for encrypt/decrypt operation, or "-" for stdin.'
    )
    parser.add_argument(
        '-o',
        '--output',
        required=True,
        action=UniqueStoreAction,
        help='Output file or directory for encrypt/decrypt operation, or - for stdout.'
    )

    parser.add_argument(
        '-c',
        '--encryption-context',
        nargs='+',
        action=UniqueStoreAction,
        help=(
            'key-value pair encryption context values (encryption only). Must a set of "key=value" pairs. '
            'ex: '
            '-c key1=value1 key2=value2'
        )
    )

    parser.add_argument(
        '--algorithm',
        action=UniqueStoreAction,
        help='Algorithm name (encryption only)',
        choices=ALGORITHM_NAMES
    )

    parser.add_argument(
        '--frame-length',
        dest='frame_length',
        type=int,
        action=UniqueStoreAction,
        help='Frame length in bytes (encryption only)'
    )

    parser.add_argument(
        '--max-length',
        type=int,
        action=UniqueStoreAction,
        help=(
            'Maximum frame length (for framed messages) or content length (for '
            'non-framed messages) (decryption only)'
        )
    )

    parser.add_argument(
        '--suffix',
        action=UniqueStoreAction,
        help='Custom suffix to use when target filename is not specified'
    )

    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Force aws-crypto to prompt you for verification before overwriting existing files'
    )

    parser.add_argument(
        '--no-overwrite',
        action='store_true',
        help='Never overwrite existing files'
    )

    parser.add_argument(
        '-r',
        '-R',
        '--recursive',
        action='store_true',
        help='Allow operation on directories as input'
    )

    parser.add_argument(
        '-v',
        dest='verbosity',
        action='count',
        help='Enables logging and sets detail level. Multiple -v options increases verbosity (max: 4).'
    )
    parser.add_argument(
        '-q',
        '--quiet',
        action='store_true',
        help='Suppresses most warning and diagnostic messages'
    )
    return parser


def _parse_kwargs(args):
    # type: (RAW_CONFIG) -> PARSED_CONFIG
    """Parses a list of CLI arguments of "key=value" form into key/values pairs.

    :param iterable args: arguments to unpack
    :returns: parsed arguments
    :rtype: dict
    :raises ParameterParseError: if a badly formed parameter if found
    """
    kwargs = defaultdict(list)  # type: Dict[str, List[str]]
    for arg in args:
        _LOGGER.debug('Attempting to parse argument: %s', arg)
        try:
            key, value = arg.split('=', 1)
            kwargs[key].append(value)
        except ValueError:
            _LOGGER.debug('Failed to parse argument')
            raise ParameterParseError('Argument parameter must follow the format "key=value"')
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

    :param list raw_config: Unprocessed encryption context
    :returns: Processed configuration
    :rtype: dict
    """
    config = copy.deepcopy(raw_config)
    parsed_config = _parse_kwargs(config)
    collapsed_config = _collapse_config(parsed_config)
    return collapsed_config


def _process_caching_config(raw_caching_config):
    # type: (RAW_CONFIG) -> CACHING_CONFIG
    """Applies additional processing to prepare the caching configuration.

    :param list raw_caching_config: Unprocessed caching configuration
    :returns: Processed caching configuration
    :rtype: dict
    :raises ParameterParseError: if invalid parameter name is found
    :raises ParameterParseError: if either capacity or max_age are not defined
    """
    _cast_types = {
        'capacity': int,
        'max_messages_encrypted': int,
        'max_bytes_encrypted': int,
        'max_age': float
    }
    parsed_config = _parse_and_collapse_config(raw_caching_config)

    if 'capacity' not in parsed_config or 'max_age' not in parsed_config:
        raise ParameterParseError('If enabling caching, both "capacity" and "max_age" are required')

    caching_config = {}  # type: Dict[str, Union[str, int, float]]
    for key, value in parsed_config.items():
        try:
            caching_config[key] = _cast_types[key](value)
        except KeyError:
            raise ParameterParseError('Invalid caching configuration key: "{}"'.format(key))
    return caching_config


def _process_master_key_provider_configs(raw_keys, action):
    # type: (List[RAW_CONFIG], str) -> List[MASTER_KEY_PROVIDER_CONFIG]
    """Applied additional processing to prepare the master key provider configuration.

    :param list raw_keys: List of master key provider configurations
    :param str action: Action defined in CLI input
    :returns: List of processed master key provider configurations
    :rtype: list of dicts
    :raises ParameterParseError: if exactly one provider value is not provided
    :raises ParameterParseError: if no key values are provided
    """
    if raw_keys is None:
        if action == 'decrypt':
            # We allow not defining any master key provider configuration if decrypting with aws-kms.
            _LOGGER.debug(
                'No master key provider config provided on decrypt request. Using aws-kms with no master keys.'
            )
            return [{'provider': 'aws-kms', 'key': []}]
        raise ParameterParseError('No master key provider configuration found.')

    processed_configs = []  # type: List[MASTER_KEY_PROVIDER_CONFIG]
    for raw_config in raw_keys:
        parsed_args = {}  # type: Dict[str, Union[str, List[str]]]
        parsed_args.update(_parse_kwargs(raw_config))

        provider = parsed_args.get('provider', ['aws-kms'])  # If no provider is defined, use aws-kms
        if len(provider) != 1:
            raise ParameterParseError(
                'Exactly one "provider" must be provided for each master key provider configuration. '
                '{} provided'.format(len(provider))
            )
        parsed_args['provider'] = provider[0]

        if 'key' not in parsed_args:
            if action == 'decrypt' and parsed_args['provider'] == 'aws-kms':
                # Special case: aws-kms does not require master key configuration for decrypt.
                parsed_args['key'] = []
            else:
                raise ParameterParseError(
                    'At least one "key" must be provided for each master key provider configuration'
                )
        processed_configs.append(parsed_args)
    return processed_configs


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
        parsed_args.master_keys = _process_master_key_provider_configs(parsed_args.master_keys, parsed_args.action)

        if parsed_args.encryption_context is not None:
            parsed_args.encryption_context = _parse_and_collapse_config(parsed_args.encryption_context)

        if parsed_args.caching is not None:
            parsed_args.caching = _process_caching_config(parsed_args.caching)
    except ParameterParseError as error:
        parser.error(*error.args)

    return parsed_args
