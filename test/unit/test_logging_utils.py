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
"""Unit testing suite for ``aws_encryption_sdk_cli.internal.logging``."""
import logging
import sys

from mock import call, MagicMock, sentinel
import pytest

from aws_encryption_sdk_cli.internal import logging_utils


@pytest.yield_fixture
def patch_logging_levels(mocker):
    mocker.patch.object(logging_utils, '_logging_levels')
    yield logging_utils._logging_levels


@pytest.yield_fixture
def patch_logging(mocker):
    mocker.patch.object(logging_utils, 'logging')
    yield logging_utils.logging


@pytest.yield_fixture
def patch_blacklist_filter(mocker):
    mocker.patch.object(logging_utils, '_BlacklistFilter')
    yield logging_utils._BlacklistFilter


@pytest.yield_fixture
def patch_kms_key_redacting_formatter(mocker):
    mocker.patch.object(logging_utils, '_KMSKeyRedactingFormatter')
    yield logging_utils._KMSKeyRedactingFormatter


@pytest.mark.parametrize('verbosity, quiet, local_level, root_level', (
    (None, False, logging.WARNING, logging.CRITICAL),
    (-1, False, logging.WARNING, logging.CRITICAL),
    (0, False, logging.WARNING, logging.CRITICAL),
    (1, False, logging.INFO, logging.CRITICAL),
    (2, False, logging.DEBUG, logging.CRITICAL),
    (3, False, logging.DEBUG, logging.INFO),
    (4, False, logging.DEBUG, logging.DEBUG),
    (99, False, logging.DEBUG, logging.DEBUG),
    (99, True, logging.CRITICAL, logging.CRITICAL)
))
def test_logging_utils_levels(verbosity, quiet, local_level, root_level):
    assert logging_utils._logging_levels(verbosity, quiet) == (local_level, root_level)


def test_setup_logger(patch_logging_levels, patch_blacklist_filter, patch_logging, patch_kms_key_redacting_formatter):
    patch_logging_levels.return_value = sentinel.local_level, sentinel.root_level
    mock_local_logger = MagicMock()
    mock_root_logger = MagicMock()
    patch_logging.getLogger.side_effect = (
        mock_local_logger,
        mock_root_logger
    )
    mock_local_handler = MagicMock()
    mock_root_handler = MagicMock()
    patch_logging.StreamHandler.side_effect = (
        mock_local_handler,
        mock_root_handler
    )
    logging_utils.setup_logger(sentinel.verbosity, sentinel.quiet)

    patch_logging_levels.assert_called_once_with(sentinel.verbosity, sentinel.quiet)
    patch_kms_key_redacting_formatter.assert_called_once_with(logging_utils.FORMAT_STRING)
    patch_logging.StreamHandler.assert_has_calls(calls=(call(), call()), any_order=True)
    mock_local_handler.setFormatter.assert_called_once_with(patch_kms_key_redacting_formatter.return_value)
    patch_logging.getLogger.assert_has_calls(
        calls=(call(logging_utils.LOGGER_NAME), call()),
        any_order=False
    )
    patch_blacklist_filter.assert_called_once_with(logging_utils.LOGGER_NAME)
    mock_root_handler.setFormatter.assert_called_once_with(patch_kms_key_redacting_formatter.return_value)
    mock_root_handler.addFilter.assert_called_once_with(patch_blacklist_filter.return_value)
    mock_local_logger.setLevel.assert_called_once_with(sentinel.local_level)
    mock_local_logger.addHandler.assert_called_once_with(mock_local_handler)
    mock_root_logger.setLevel.assert_called_once_with(sentinel.root_level)
    mock_root_logger.addHandler.assert_called_once_with(mock_root_handler)


def test_blacklist_filter():
    class FakeRecord(object):
        """Custom fake class because "name" is a reserved name for mocks."""

        def __init__(self, name):
            self.name = name
    test = logging_utils._BlacklistFilter(sentinel.a, sentinel.b)

    assert test._BlacklistFilter__blacklist == (sentinel.a, sentinel.b)
    assert test.filter(FakeRecord(name=sentinel.c))
    assert not test.filter(FakeRecord(name=sentinel.b))


@pytest.mark.parametrize('record, plaintext, expected', (
    (  # kms:GenerateDataKey or kms:Decrypt response
        logging.LogRecord(
            name='botocore.parsers',
            level=logging.DEBUG,
            pathname='a_path_name',
            lineno=0,
            msg='Response body:\n%s',
            args=((
                b'{"CiphertextBlob":"AQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBA'
                b'DBoBgkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDLozVMQGN3lHKyOlfwIBEIA7Rm/ZI8DKfmto0UhG5BGpmVwAGIzhc/9I3fp4m'
                b'TWaZJpfSPLKCf0uPRmgXHwKAIhV5W4MYCwPjIRqDbw=","KeyId":"arn:aws:kms:us-west-2:658956600833:key/b3537ef'
                b'1-d8dc-4780-9f5a-55776cbb2f7f","Plaintext":"5OAq/2/qUiytQmHVcFso2czUz/BRK/YwktO4JLSNrD8="}'
            ),),
            exc_info=None
        ),
        '5OAq/2/qUiytQmHVcFso2czUz/BRK/YwktO4JLSNrD8=',
        (
            'Response body:\n'
            '{"CiphertextBlob": "AQEBAHhA84wnXjEJdBbBBylRUFcZZK2j7xwh6UyLoL28nQ+0FAAAAH4wfAYJKoZIhvcNAQcGoG8wbQIBADBoB'
            'gkqhkiG9w0BBwEwHgYJYIZIAWUDBAEuMBEEDLozVMQGN3lHKyOlfwIBEIA7Rm/ZI8DKfmto0UhG5BGpmVwAGIzhc/9I3fp4mTWaZJpfSP'
            'LKCf0uPRmgXHwKAIhV5W4MYCwPjIRqDbw=", "KeyId": "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-'
            '9f5a-55776cbb2f7f", "Plaintext": "<**-redacted-**>"}'
        )
    ),
    (  # kms:Encrypt request
        logging.LogRecord(
            name='botocore.endpoint',
            level=logging.DEBUG,
            pathname='a_path_name',
            lineno=0,
            msg='Making request for %s (verify_ssl=%s) with params: %s',
            args=(
                'OperationModel(name=Encrypt)',
                True,
                {
                    'url_path': '/',
                    'query_string': '',
                    'method': 'POST',
                    'headers': {
                        'X-Amz-Target': 'TrentService.Encrypt',
                        'Content-Type': 'application/x-amz-json-1.1',
                        'User-Agent': 'Boto3/1.4.5 Python/3.6.2 Darwin/16.7.0 Botocore/1.7.21'
                    },
                    'body': (
                        b'{'
                        b'"KeyId": "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f", '
                        b'"Plaintext": "c29tZSBzdXBlciBzZWNyZXQgZGF0YQ=="'
                        b'}'
                    ),
                    'url': 'https://kms.us-west-2.amazonaws.com/',
                    'context': {
                        'client_region': 'us-west-2',
                        # Normally there is a "client_config" entry here with a botocore.config.Config object.
                        # Removing that from this test case because it does not have a consistent repr value.
                        'has_streaming_input': False,
                        'auth_type': None
                    }
                }
            ),
            exc_info=None
        ),
        'c29tZSBzdXBlciBzZWNyZXQgZGF0YQ==',
        (
            """Making request for OperationModel(name=Encrypt) (verify_ssl=True) with params: {'url_path': '/', 'que"""
            """ry_string': '', 'method': 'POST', 'headers': {'X-Amz-Target': 'TrentService.Encrypt', 'Content-Type':"""
            """ 'application/x-amz-json-1.1', 'User-Agent': 'Boto3/1.4.5 Python/3.6.2 Darwin/16.7.0 Botocore/1.7.21'"""
            """}, 'body': '{"KeyId": "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f","""
            """ "Plaintext": "<**-redacted-**>"}', 'url': 'https://kms.us-west-2.amazonaws.com/', 'context': {'clien"""
            """t_region': 'us-west-2', 'has_streaming_input': False, 'auth_type': None}}"""
        )
    ),
))
def test_kms_key_redacting_formatter(record, plaintext, expected):
    formatter = logging_utils._KMSKeyRedactingFormatter('%(message)s')
    test = formatter.format(record)

    assert '<**-redacted-**>' in test
    assert plaintext not in test
    if sys.version >= '3.6':
        # Dictionaries are only ordered in Python 3.6+
        assert test == expected
