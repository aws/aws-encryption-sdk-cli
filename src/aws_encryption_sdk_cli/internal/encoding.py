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
from typing import IO, Iterable, List, Optional  # noqa pylint: disable=unused-import
from types import TracebackType  # noqa pylint: disable=unused-import

import six

from aws_encryption_sdk_cli.internal.logging_utils import LOGGER_NAME

_LOGGER = logging.getLogger(LOGGER_NAME)
__all__ = ('Base64IO',)


class Base64IO(io.IOBase):
    """Wraps a stream, base64-decoding read results before returning them.

    .. note::

        Provides iterator and context manager interfaces. Writes must be performed using
        the context manager interface.

    :param wrapped: Stream to wrap
    :param bool close_wrapped_on_close: Should the wrapped stream be closed when this object is closed (default: False)
    """

    __finalize = False
    __in_context_manager = False
    closed = False

    def __init__(self, wrapped, close_wrapped_on_close=False):
        # type: (IO, Optional[bool]) -> None
        """Check for required methods on wrapped stream and set up read buffer."""
        required_attrs = ('read', 'write', 'close', 'closed', 'flush')
        if not all(hasattr(wrapped, attr) for attr in required_attrs):
            raise TypeError('Base64IO wrapped object must have attributes: {}'.format(repr(sorted(required_attrs))))
        super(Base64IO, self).__init__()
        self.__wrapped = wrapped
        self.__close_wrapped_on_close = close_wrapped_on_close
        self.__read_buffer = b''
        self.__write_buffer = b''

    def __enter__(self):
        # type: () -> Base64IO
        """Return self on enter."""
        self.__in_context_manager = True
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # type: (type, BaseException, TracebackType) -> None
        """Properly close self on exit."""
        self.close()
        self.__in_context_manager = False

    def close(self):
        # type: () -> None
        """Closes this stream, encoding and writing any buffered bytes is present.

        .. note::

            This does **not** close the wrapped stream unless otherwise specified when this
            object was created.
        """
        self.__finalize = True
        if self.__write_buffer:
            self.write(b'')
        self.closed = True
        if self.__close_wrapped_on_close:
            self.__wrapped.close()

    def _passthrough_interactive_check(self, method_name, mode):
        # type: (str, str) -> bool
        """Attempts to call the specified method on the wrapped stream and return the result.
        If the method is not found on the wrapped stream, returns False.

        .. note::

            Special Case: If wrapped stream is a Python 2 file, returns True.

        :param str method_name: Name of method to call
        :param str mode: Python 2 mode character
        :rtype: bool
        """
        try:
            return getattr(self.__wrapped, method_name)()
        except AttributeError:
            if six.PY2 and isinstance(self.__wrapped, file):  # noqa pylint: disable=undefined-variable
                if mode in self.__wrapped.mode:
                    return True
            return False

    def writable(self):
        # type: () -> bool
        """Determine if the stream can be written to.
        Delegates to wrapped stream if present.
        Otherwise returns False.

        :rtype: bool
        """
        return self._passthrough_interactive_check('writable', 'w')

    def readable(self):
        # type: () -> bool
        """Determine if the stream can be read from.
        Delegates to wrapped stream if present.
        Otherwise returns False.

        :rtype: bool
        """
        return self._passthrough_interactive_check('readable', 'r')

    def flush(self):
        # type: () -> None
        """Flushes the write buffer of the wrapped stream."""
        return self.__wrapped.flush()

    def write(self, b):
        # type: (bytes) -> int
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

        if not self.writable():
            raise IOError('Stream is not writable')

        # Load any stashed bytes and clear the buffer
        _bytes_to_write = self.__write_buffer + b
        self.__write_buffer = b''

        # If an even base64 chunk or finalizing the stream, write through.
        if len(_bytes_to_write) % 3 == 0 or self.__finalize:
            return self.__wrapped.write(base64.b64encode(_bytes_to_write))

        # We're not finalizing the stream, so stash the trailing bytes and encode the rest.
        trailing_byte_pos = -1 * (len(_bytes_to_write) % 3)
        self.__write_buffer = _bytes_to_write[trailing_byte_pos:]
        return self.__wrapped.write(base64.b64encode(_bytes_to_write[:trailing_byte_pos]))

    def writelines(self, lines):
        # type: (Iterable[bytes]) -> None
        """Write a list of lines.

        :param list lines: Lines to write
        """
        for line in lines:
            self.write(line)

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

        if not self.readable():
            raise IOError('Stream is not readable')

        _bytes_to_read = None
        if b is not None:
            # Calculate number of encoded bytes that must be read to get b raw bytes.
            _bytes_to_read = int((b - len(self.__read_buffer)) * 4 / 3)
            _bytes_to_read += (4 - _bytes_to_read % 4)

        _LOGGER.debug('%s bytes requested: reading %s bytes from wrapped stream', b, _bytes_to_read)

        # Read encoded bytes from wrapped stream.
        data = self.__wrapped.read(_bytes_to_read)

        results = io.BytesIO()
        # First, load any stashed bytes
        results.write(self.__read_buffer)
        # Decode encoded bytes.
        results.write(base64.b64decode(data))

        results.seek(0)
        output_data = results.read(b)
        # Stash any extra bytes for the next run.
        self.__read_buffer = results.read()

        return output_data

    def __iter__(self):
        # type: () -> Base64IO
        """Iterate with this class, not the wrapped stream."""
        return self

    def readline(self, limit=-1):
        # type: (int) -> bytes
        """Readline with this class, not the wrapped stream."""
        return self.read(limit if limit > 0 else io.DEFAULT_BUFFER_SIZE)

    def readlines(self, hint=-1):
        # type: (hint) -> List[bytes]
        """Readlines with this class, not the wrapped stream."""
        lines = []
        for line in self:
            lines.append(line)
            if hint > 0 and len(lines) * io.DEFAULT_BUFFER_SIZE > hint:
                break
        return lines

    def __next__(self):
        # type: () -> bytes
        """Iterate with this class, not the wrapped stream (Python 3 hook)."""
        line = self.readline()
        if line:
            return line
        raise StopIteration()

    def next(self):
        # type: () -> bytes
        """Iterate with this class, not the wrapped stream (Python 2 hook)."""
        return self.__next__()
