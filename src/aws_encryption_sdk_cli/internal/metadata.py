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
import json
import os
from typing import Any, IO, Optional  # noqa pylint: disable=unused-import

import attr


@attr.s(hash=False, init=False)
class MetadataWriter(object):
    # pylint: disable=too-few-public-methods
    """Writes JSON-encoded metadata to output stream unless suppressed.

    :param bool suppress_output: Should output be suppressed
    :param output_stream: file-like stream to which to write encoded metadata (optional)
    :raises AttributeError: if suppress_output is False and output_stream was not provided
    :raises AttributeError: if suppress_output is False and output_stream does not have a "write" method
    """

    suppress_output = attr.ib(validator=attr.validators.instance_of(bool))
    output_stream = attr.ib(default=None)

    def __init__(self, suppress_output, output_stream=None):
        # type: (bool, Optional[IO]) -> None
        """Workaround pending resolution of attrs/mypy interaction.
        https://github.com/python/mypy/issues/2088
        https://github.com/python-attrs/attrs/issues/215
        """
        self.suppress_output = suppress_output
        self.output_stream = output_stream
        attr.validate(self)

        if not self.suppress_output:
            if self.output_stream is None:
                raise AttributeError('output_stream must be specified when suppress_output is False.')

            try:
                callable(self.output_stream.write)
            except AttributeError:
                raise AttributeError('Metadata output stream must have "write" method.')

    def write_metadata(self, **metadata):
        # type: (**Any) -> Optional[int]
        """Writes metadata to the output stream if output is not suppressed.

        :param **metadata: JSON-serializeable metadata kwargs to write
        """
        if self.suppress_output:
            return 0  # wrote 0 bytes

        metadata_line = json.dumps(metadata, sort_keys=True)
        return self.output_stream.write(metadata_line + os.linesep)
