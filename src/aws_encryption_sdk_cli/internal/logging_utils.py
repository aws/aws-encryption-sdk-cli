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
import codecs
import copy
import json
import logging

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, Sequence, Text, Union, cast  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    cast = lambda typ, val: val  # noqa pylint: disable=invalid-name
    # We only actually need the other imports when running the mypy checks

__all__ = ("setup_logger", "LOGGER_NAME")
LOGGING_LEVELS = {0: logging.CRITICAL, 1: logging.INFO, 2: logging.DEBUG}  # type: Dict[int, int]
LOGGER_NAME = "aws_encryption_sdk_cli"  # type: str
FORMAT_STRING = "%(asctime)s - %(threadName)s - %(name)s - %(levelname)s - %(message)s"  # type: str
MAX_LOGGING_LEVEL = 2  # type: int
_REDACTED = "<**-redacted-**>"  # type: str


class _KMSKeyRedactingFormatter(logging.Formatter):
    """Log formatter that redacts ``Plaintext`` values from KMS request and response bodies."""

    def __to_str(self, value):  # pylint: disable=no-self-use
        # type: (Union[Text, str, bytes]) -> Text
        """Converts bytes or str to str.

        :param value: Value to convert
        :type value: bytes or str
        :rtype: str
        """
        if isinstance(value, bytes):
            return codecs.decode(value, "utf-8")
        return value

    def __is_kms_encrypt_request(self, record):  # pylint: disable=no-self-use
        # type: (logging.LogRecord) -> bool
        """Determine if a record contains a kms:Encrypt request.

        :param record: Logging record to filter
        :type record: logging.LogRecord
        :rtype: bool
        """
        try:
            return all(
                (
                    record.name == "botocore.endpoint",
                    record.msg.startswith("Making request"),
                    cast(tuple, record.args)[-1]["headers"]["X-Amz-Target"] == "TrentService.Encrypt",
                )
            )
        except Exception:  # pylint: disable=broad-except
            return False

    def __redact_encrypt_request(self, record):
        # type: (logging.LogRecord) -> None
        """Redact the ``Plaintext`` value from a kms:Encrypt request.

        :param record: Logging record to filter
        :type record: logging.LogRecord
        """
        try:
            parsed_body = json.loads(self.__to_str(cast(tuple, record.args)[-1]["body"]))
            parsed_body["Plaintext"] = _REDACTED
            cast(tuple, record.args)[-1]["body"] = json.dumps(parsed_body, sort_keys=True)
        except Exception:  # pylint: disable=broad-except
            return

    def __is_kms_response_with_plaintext(self, record):  # pylint: disable=no-self-use
        # type: (logging.LogRecord) -> bool
        """Determine if a record contains a KMS response with plaintext.

        :param record: Logging record to filter
        :type record: logging.LogRecord
        :rtype: bool
        """
        try:
            return all(
                (
                    record.name == "botocore.parsers",
                    record.msg.startswith("Response body:"),
                    b"KeyId" in cast(tuple, record.args)[0],
                    b"Plaintext" in cast(tuple, record.args)[0],
                )
            )
        except Exception:  # pylint: disable=broad-except
            return False

    def __redact_key_from_response(self, record):
        # type: (logging.LogRecord) -> None
        """Redact the ``Plaintext`` value from a KMS response body.

        :param record: Logging record to filter
        :type record: logging.LogRecord
        """
        try:
            parsed_body = json.loads(self.__to_str(cast(tuple, record.args)[0]))
            parsed_body["Plaintext"] = _REDACTED
            new_args = (json.dumps(parsed_body, sort_keys=True),) + cast(tuple, record.args)[1:]
            record.args = new_args
        except Exception:  # pylint: disable=broad-except
            return

    def __redact_record(self, record):
        # type: (logging.LogRecord) -> logging.LogRecord
        """Redact any values from a record, as necessary.

        :param record: Logging record to filter
        :type record: logging.LogRecord
        """
        _record = copy.deepcopy(record)
        if self.__is_kms_encrypt_request(_record):
            self.__redact_encrypt_request(_record)
        elif self.__is_kms_response_with_plaintext(_record):
            self.__redact_key_from_response(_record)
        return _record

    def format(self, record):
        # type: (logging.LogRecord) -> str
        """Format the specified record as text, redacting plaintext KMS data keys if found.

        :param record: Logging record to filter
        :type record: logging.LogRecord
        """
        _record = self.__redact_record(record)
        return super(_KMSKeyRedactingFormatter, self).format(_record)


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

    formatter = _KMSKeyRedactingFormatter(FORMAT_STRING)

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
