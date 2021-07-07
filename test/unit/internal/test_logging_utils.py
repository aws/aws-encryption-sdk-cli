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

import pytest
from mock import MagicMock, call, sentinel

from aws_encryption_sdk_cli.internal import logging_utils

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def patch_logging_levels(mocker):
    mocker.patch.object(logging_utils, "_logging_levels")
    yield logging_utils._logging_levels


@pytest.fixture
def patch_logging(mocker):
    mocker.patch.object(logging_utils, "logging")
    yield logging_utils.logging


@pytest.fixture
def patch_blacklist_filter(mocker):
    mocker.patch.object(logging_utils, "_BlacklistFilter")
    yield logging_utils._BlacklistFilter


@pytest.fixture
def patch_kms_key_redacting_formatter(mocker):
    mocker.patch.object(logging_utils, "_KMSKeyRedactingFormatter")
    yield logging_utils._KMSKeyRedactingFormatter


@pytest.mark.parametrize(
    "verbosity, quiet, local_level, root_level",
    (
        (None, False, logging.WARNING, logging.CRITICAL),
        (-1, False, logging.WARNING, logging.CRITICAL),
        (0, False, logging.WARNING, logging.CRITICAL),
        (1, False, logging.INFO, logging.CRITICAL),
        (2, False, logging.DEBUG, logging.CRITICAL),
        (3, False, logging.DEBUG, logging.INFO),
        (4, False, logging.DEBUG, logging.DEBUG),
        (99, False, logging.DEBUG, logging.DEBUG),
        (99, True, logging.CRITICAL, logging.CRITICAL),
    ),
)
def test_logging_utils_levels(verbosity, quiet, local_level, root_level):
    assert logging_utils._logging_levels(verbosity, quiet) == (local_level, root_level)


def test_setup_logger(patch_logging_levels, patch_blacklist_filter, patch_logging, patch_kms_key_redacting_formatter):
    patch_logging_levels.return_value = sentinel.local_level, sentinel.root_level
    mock_local_logger = MagicMock()
    mock_root_logger = MagicMock()
    patch_logging.getLogger.side_effect = (mock_local_logger, mock_root_logger)
    mock_local_handler = MagicMock()
    mock_root_handler = MagicMock()
    patch_logging.StreamHandler.side_effect = (mock_local_handler, mock_root_handler)
    logging_utils.setup_logger(sentinel.verbosity, sentinel.quiet)

    patch_logging_levels.assert_called_once_with(sentinel.verbosity, sentinel.quiet)
    patch_kms_key_redacting_formatter.assert_called_once_with(logging_utils.FORMAT_STRING)
    patch_logging.StreamHandler.assert_has_calls(calls=(call(), call()), any_order=True)
    mock_local_handler.setFormatter.assert_called_once_with(patch_kms_key_redacting_formatter.return_value)
    patch_logging.getLogger.assert_has_calls(calls=(call(logging_utils.LOGGER_NAME), call()), any_order=False)
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
