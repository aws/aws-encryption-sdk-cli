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
"""Utilities for handling operation metadata."""
import base64
import codecs
from enum import Enum
import json
import os
import sys
from typing import Any, Dict, IO, Optional, Text  # noqa pylint: disable=unused-import
from types import TracebackType  # noqa pylint: disable=unused-import

import attr
from aws_encryption_sdk.structures import MessageHeader  # noqa pylint: disable=unused-import
import six


@attr.s(hash=False, init=False, cmp=True)
class MetadataWriter(object):
    # pylint: disable=too-few-public-methods
    """Writes JSON-encoded metadata to output stream unless suppressed.

    :param bool suppress_output: Should output be suppressed
    :param str output_mode: File mode to use when writing to ``output_file`` (optional)
    :raises AttributeError: if suppress_output is False and output_stream was not provided
    :raises AttributeError: if suppress_output is False and output_stream does not have a "write" method
    """

    suppress_output = attr.ib(validator=attr.validators.instance_of(bool))
    output_mode = attr.ib(
        validator=attr.validators.optional(attr.validators.in_(['w', 'a'])),
        default=None
    )
    output_file = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(six.string_types)),
        default=None
    )
    output_stream = None  # type: IO

    def __init__(self, suppress_output, output_mode=None):
        # type: (bool, Optional[str]) -> None
        """Workaround pending resolution of attrs/mypy interaction.
        https://github.com/python/mypy/issues/2088
        https://github.com/python-attrs/attrs/issues/215
        """
        self.suppress_output = suppress_output
        self.output_mode = output_mode

        if not self.suppress_output:
            if self.output_mode is None:
                raise TypeError('output_mode cannot be None when suppress_output is False')

    def __call__(self, output_file=None):
        # type: (Optional[str]) -> MetadataWriter
        """Set the output file target and validate init and call arguments.

        .. note::
            Separated from ``__init__`` to make use as an argparse type simpler.

        :param str output_file: Path to file to write to, or "-" for stdout (optional)
        """
        self.output_file = output_file
        attr.validate(self)

        if not self.suppress_output:
            if self.output_file is None:
                raise TypeError('output_file cannot be None when suppress_output is False')

            if self.output_file == '-' and self.output_mode == 'a':
                raise ValueError('output_mode must be "w" when output_file is stdout')

        return self

    def open(self):
        # type: () -> None
        """Create and open the output stream."""
        if not self.suppress_output:
            if self.output_file == '-':
                self.output_stream = sys.stdout
            else:
                self.output_stream = open(self.output_file, self.output_mode)

    def __enter__(self):
        # type: () -> MetadataWriter
        """Create and open the output stream on enter."""
        self.open()
        return self

    def close(self):
        # type: () -> None
        """Flush and close the output stream."""
        if self.output_stream is not None:
            self.output_stream.flush()
            if self.output_stream is not sys.stdout:
                self.output_stream.close()

    def __exit__(self, exc_type, exc_value, traceback):
        # type: (type, BaseException, TracebackType) -> None
        """Flush and close the output stream on close."""
        self.close()

    def write_metadata(self, **metadata):
        # type: (**Any) -> Optional[int]
        """Writes metadata to the output stream if output is not suppressed.

        :param **metadata: JSON-serializeable metadata kwargs to write
        """
        if self.suppress_output:
            return 0  # wrote 0 bytes

        metadata_line = json.dumps(metadata, sort_keys=True)
        return self.output_stream.write(metadata_line + os.linesep)


def _unicode_b64_encode(value):
    # type: (bytes) -> Text
    """"""
    return codecs.decode(base64.b64encode(value), 'utf-8')


def json_ready_header(header):
    # type: (MessageHeader) -> Dict[str, Any]
    """Create a JSON-serializable representation of a :class:`aws_encryption_sdk.structures.MessageHeader`.

    :param header: header for which to create a JSON-serializable representation
    :type header: aws_encryption_sdk.structures.MessageHeader
    :rtype: dict
    """
    dict_header = attr.asdict(header)

    dict_header['version'] = str(float(dict_header['version'].value))
    dict_header['algorithm'] = dict_header['algorithm'].name

    for key, value in dict_header.items():
        if isinstance(value, Enum):
            dict_header[key] = value.value

    dict_header['message_id'] = _unicode_b64_encode(dict_header['message_id'])

    dict_header['encrypted_data_keys'] = sorted(
        list(dict_header['encrypted_data_keys']),
        key=lambda x: six.b(x['key_provider']['provider_id']) + x['key_provider']['key_info']
    )
    for data_key in dict_header['encrypted_data_keys']:
        data_key['key_provider']['provider_id'] = _unicode_b64_encode(six.b(data_key['key_provider']['provider_id']))
        data_key['key_provider']['key_info'] = _unicode_b64_encode(data_key['key_provider']['key_info'])
        data_key['encrypted_data_key'] = _unicode_b64_encode(data_key['encrypted_data_key'])

    return dict_header
