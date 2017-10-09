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
"""Logging utility tooling."""
import logging
from typing import Dict, Sequence, Text, Union  # noqa pylint: disable=unused-import

LOGGING_LEVELS = {
    0: logging.CRITICAL,
    1: logging.INFO,
    2: logging.DEBUG
}  # type: Dict[int, int]
LOGGER_NAME = 'aws_encryption_sdk_cli'  # type: str
FORMAT_STRING = '%(levelname)s:%(name)s:%(message)s'  # type: str
MAX_LOGGING_LEVEL = 2  # type: int


class _BlacklistFilter(logging.Filter):  # pylint: disable=too-few-public-methods
    """Logging filter that allows blacklisting of certain logger names.

    :param str *args: logger names to ignore
    """

    def __init__(self, *args):
        # type: (Union[Text, str]) -> None
        """Creates internal blacklist."""
        super(_BlacklistFilter, self).__init__()
        self.__blacklist = args

    def filter(self, record):
        # type: (logging.LogRecord) -> bool
        """Determines whether to filter record.

        :param record: Logging record to filter
        :type record: logging.LogRecord
        :rtype: bool
        """
        return record.name not in self.__blacklist


def _logging_levels(verbosity, quiet):
    # type: (int, bool) -> Sequence[int]
    """Determines the proper logging levels given required verbosity level and quiet.

    :param int verbosity: Requested level of verbosity
    :param bool quiet: Suppresses all logging when true
    :returns: local and root logging levels
    :rtype: list of int
    """
    if quiet:
        return logging.CRITICAL, logging.CRITICAL

    if verbosity is None or verbosity <= 0:
        return logging.WARNING, logging.CRITICAL

    normalized_local = min(verbosity, MAX_LOGGING_LEVEL)
    normalized_root = min(verbosity - normalized_local, MAX_LOGGING_LEVEL)
    return LOGGING_LEVELS[normalized_local], LOGGING_LEVELS[normalized_root]


def setup_logger(verbosity, quiet):
    # type: (int, bool) -> None
    """Sets up the logger.

    :param int verbosity: Requested level of verbosity
    :param bool quiet: Suppresses all logging when true
    """
    local_logging_level, root_logging_level = _logging_levels(verbosity, quiet)

    formatter = logging.Formatter(FORMAT_STRING)

    local_handler = logging.StreamHandler()
    local_handler.setFormatter(formatter)

    local_logger = logging.getLogger(LOGGER_NAME)
    local_logger.setLevel(local_logging_level)
    local_logger.addHandler(local_handler)

    root_handler = logging.StreamHandler()
    root_handler.setFormatter(formatter)
    root_handler.addFilter(_BlacklistFilter(LOGGER_NAME))

    root_logger = logging.getLogger()
    root_logger.setLevel(root_logging_level)
    root_logger.addHandler(root_handler)
