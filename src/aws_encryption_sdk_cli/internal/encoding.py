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
"""Base64 context manager."""
from __future__ import division
import base64
import io
import logging
from typing import IO, List, Optional  # noqa pylint: disable=unused-import
from types import TracebackType  # noqa pylint: disable=unused-import

from wrapt import ObjectProxy

from aws_encryption_sdk_cli.internal.logging_utils import LOGGER_NAME

_LOGGER = logging.getLogger(LOGGER_NAME)
__all__ = ('Base64IO',)


class Base64IO(ObjectProxy):
    """Wraps a stream, base64-decoding read results before returning them.

    :param wrapped: Stream to wrap
    """

    # Prime ObjectProxy's attributes to allow setting in init.
    __read_buffer = None
    __write_buffer = None
    __finalize = False
    __in_context_manager = False
    closed = False
    seekable = False

    def __init__(self, wrapped):
        # type: (IO) -> None
        """Check for required methods on wrapped stream and set up read buffer."""
        required_attrs = ('read', 'write', 'close', 'closed')
        if not all(hasattr(wrapped, attr) for attr in required_attrs):
            raise TypeError('Base64IO wrapped object must have attributes: {}'.format(repr(sorted(required_attrs))))
        super(Base64IO, self).__init__(wrapped)
        self.__read_buffer = b''
        self.__write_buffer = b''

    def __enter__(self):
        # type: () -> Base64IO
        """Return self on enter."""
        self.__in_context_manager = True
        return self

    def __exit__(self, exc_type, exc_value, traceback):  # ObjectProxy exit confuses pylint: disable=arguments-differ
        # type: (type, BaseException, TracebackType) -> None
        """Properly close self on exit."""
        self.close()
        self.__in_context_manager = False

    def seek(self, offset, whence=0):  # pylint: disable=unused-argument,no-self-use
        # type: (int, int) -> None
        """Seek is not allowed on Base64IO objects."""
        raise IOError('Seek not allowed on Base64IO objects')

    def close(self):
        # type: () -> None
        """Closes this stream, encoding and writing any buffered bytes is present.

        .. note::

            This does **not** close the wrapped stream.
        """
        self.__finalize = True
        if self.__write_buffer:
            self.write(b'')
        self.closed = True

    def write(self, b):
        # type: (bytes) -> None
        """Base64-encode the bytes and write them to the wrapped stream, buffering any
        bytes that would require padding for the next write call.

        .. warning::

            Because up to two bytes of data must be buffered to ensure correct base64 encoding
            of all data written, this method is disabled except when the Base64IO object is
            used as a context manager. This is enforced in order to ensure that your data
            is not corrupted.

        :param bytes b: Bytes to write to wrapped stream
        :raises ValueError: if called on closed Base64IO object
        :raises ValueError: if called on Base64IO object outside of a context manager
        """
        if not self.__in_context_manager:
            raise ValueError('Writes are only allowed on Base64IO objects when used as context managers.')

        if self.closed:
            raise ValueError('I/O operation on closed file.')

        # Load any stashed bytes and clear the buffer
        _bytes_to_write = self.__write_buffer + b
        self.__write_buffer = b''

        # If an even base64 chunk or finalizing the stream, write through.
        if len(_bytes_to_write) % 3 == 0 or self.__finalize:
            return self.__wrapped__.write(base64.b64encode(_bytes_to_write))

        # We're not finalizing the stream, so stash the trailing bytes and encode the rest.
        trailing_byte_pos = -1 * (len(_bytes_to_write) % 3)
        self.__write_buffer = _bytes_to_write[trailing_byte_pos:]
        return self.__wrapped__.write(base64.b64encode(_bytes_to_write[:trailing_byte_pos]))

    def read(self, b=None):
        # type: (Optional[int]) -> bytes
        """Read bytes from source stream base64-decoding before return, and adjusting read
        from wrapped stream to return correct number of bytes.

        :param int b: Number of bytes to read
        :returns: Decoded bytes from wrapped stream
        :rtype: bytes
        """
        if self.closed:
            raise ValueError('I/O operation on closed file.')

        _bytes_to_read = None
        if b is not None:
            # Calculate number of encoded bytes that must be read to get b raw bytes.
            _bytes_to_read = int((b - len(self.__read_buffer)) * 4 / 3)
            _bytes_to_read += (4 - _bytes_to_read % 4)

        _LOGGER.debug('%s bytes requested: adjusted to %s bytes', b, _bytes_to_read)

        # Read encoded bytes from wrapped stream.
        data = self.__wrapped__.read(_bytes_to_read)
        _LOGGER.debug('read %d bytes from source', len(data))

        results = io.BytesIO()
        _LOGGER.debug('loading %d stashed bytes', len(self.__read_buffer))
        # First, load any stashed bytes
        results.write(self.__read_buffer)
        # Decode encoded bytes.
        results.write(base64.b64decode(data))

        results.seek(0)
        output_data = results.read(b)
        _LOGGER.debug('returning %d bytes', len(output_data))
        # Stash any extra bytes for the next run.
        self.__read_buffer = results.read()
        _LOGGER.debug('stashing %d bytes', len(self.__read_buffer))

        if not output_data:
            self.__wrapped__.close()
        return output_data

    def __iter__(self):
        # type: () -> Base64IO
        """Iterate with this class, not the wrapped stream."""
        return self

    def readline(self):
        # type: () -> bytes
        """Readline with this class, not the wrapped stream."""
        return self.read(io.DEFAULT_BUFFER_SIZE)

    def readlines(self):
        # type: () -> List[bytes]
        """Readlines with this class, not the wrapped stream."""
        return [line for line in self]

    def __next__(self):
        # type: () -> bytes
        """Iterate with this class, not the wrapped stream (Python 3 hook)."""
        if self.__wrapped__.closed and not self.__read_buffer:
            raise StopIteration()
        return self.readline()

    def next(self):
        # type: () -> bytes
        """Iterate with this class, not the wrapped stream (Python 2 hook)."""
        return self.__next__()
