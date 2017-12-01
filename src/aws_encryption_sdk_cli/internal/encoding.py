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
import string
from types import TracebackType  # noqa pylint: disable=unused-import

import six

from aws_encryption_sdk_cli.internal.logging_utils import LOGGER_NAME

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import IO, Iterable, List, Optional  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

__all__ = ('Base64IO',)
_LOGGER = logging.getLogger(LOGGER_NAME)


class Base64IO(io.IOBase):
    """Wraps a stream, base64-decoding read results before returning them and base64-encoding
    written bytes before writing them to the stream. Unless ``close_wrapped_on_close`` is
    set to True, the underlying stream is not closed when this object is closed. Instances
    of this class are not reusable in order maintain consistency with the :class:`io.IOBase`
    behavior on ``close()``.

    .. note::

        Provides iterator and context manager interfaces.

    .. warning::

        Because up to two bytes of data must be buffered to ensure correct base64 encoding
        of all data written, this object **must** be closed after you are done writing to
        avoid data loss. If used as a context manager, we take care of that for you.

    :param wrapped: Stream to wrap
    :param bool close_wrapped_on_close: Should the wrapped stream be closed when this object is closed (default: False)
    """

    closed = False

    def __init__(self, wrapped, close_wrapped_on_close=False):
        # type: (Base64IO, IO, Optional[bool]) -> None
        """Check for required methods on wrapped stream and set up read buffer.

        :raises TypeError: if ``wrapped`` does not have attributes needed to determine the stream's state
        """
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
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # type: (type, BaseException, TracebackType) -> None
        """Properly close self on exit."""
        self.close()

    def close(self):
        # type: () -> None
        """Closes this stream, encoding and writing any buffered bytes is present.

        .. note::

            This does **not** close the wrapped stream unless otherwise specified when this
            object was created.
        """
        if self.__write_buffer:
            self.__wrapped.write(base64.b64encode(self.__write_buffer))
            self.__write_buffer = b''
        self.closed = True
        if self.__close_wrapped_on_close:
            self.__wrapped.close()

    def _passthrough_interactive_check(self, method_name, mode):
        # type: (str, str) -> bool
        """Attempt to call the specified method on the wrapped stream and return the result.
        If the method is not found on the wrapped stream, returns False.

        .. note::

            Special Case: If wrapped stream is a Python 2 file, inspect the file mode.

        :param str method_name: Name of method to call
        :param str mode: Python 2 mode character
        :rtype: bool
        """
        try:
            method = getattr(self.__wrapped, method_name)
        except AttributeError:
            if six.PY2 and isinstance(self.__wrapped, file):  # noqa pylint: disable=undefined-variable
                if mode in self.__wrapped.mode:
                    return True
            return False
        else:
            return method()

    def writable(self):
        # type: () -> bool
        """Determine if the stream can be written to.
        Delegates to wrapped stream when possible.
        Otherwise returns False.

        :rtype: bool
        """
        return self._passthrough_interactive_check('writable', 'w')

    def readable(self):
        # type: () -> bool
        """Determine if the stream can be read from.
        Delegates to wrapped stream when possible.
        Otherwise returns False.

        :rtype: bool
        """
        return self._passthrough_interactive_check('readable', 'r')

    def flush(self):
        # type: () -> None
        """Flush the write buffer of the wrapped stream."""
        return self.__wrapped.flush()

    def write(self, b):
        # type: (bytes) -> int
        """Base64-encode the bytes and write them to the wrapped stream, buffering any
        bytes that would require padding for the next write call.

        .. warning::

            Because up to two bytes of data must be buffered to ensure correct base64 encoding
            of all data written, this object **must** be closed after you are done writing to
            avoid data loss. If used as a context manager, we take care of that for you.

        :param bytes b: Bytes to write to wrapped stream
        :raises ValueError: if called on closed Base64IO object
        :raises IOError: if underlying stream is not writable
        """
        if self.closed:
            raise ValueError('I/O operation on closed file.')

        if not self.writable():
            raise IOError('Stream is not writable')

        # Load any stashed bytes and clear the buffer
        _bytes_to_write = self.__write_buffer + b
        self.__write_buffer = b''

        # If an even base64 chunk or finalizing the stream, write through.
        if len(_bytes_to_write) % 3 == 0:
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

    def _read_additional_data_removing_whitespace(self, data, total_bytes_to_read):
        # type: (bytes, int) -> bytes
        """Read additional data from wrapped stream, removing any whitespace found, until we
        reach the desired number of bytes.

        :param bytes data: Data that has already been read from wrapped stream
        :param int total_bytes_to_read: Number of total non-whitespace bytes to read from wrapped stream
        :returns: ``total_bytes_to_read`` bytes from wrapped stream with no whitespace
        :rtype: bytes
        """
        if total_bytes_to_read is None:
            # If the requested number of bytes is None, we read the entire message, in which
            # case the base64 module happily removes any whitespace.
            return data

        _data_buffer = io.BytesIO()
        _data_buffer.write(b''.join(data.split()))
        _remaining_bytes_to_read = total_bytes_to_read - _data_buffer.tell()

        while _remaining_bytes_to_read > 0:
            _raw_additional_data = self.__wrapped.read(_remaining_bytes_to_read)
            if not _raw_additional_data:
                # No more data to read from wrapped stream.
                break

            _data_buffer.write(b''.join(_raw_additional_data.split()))
            _remaining_bytes_to_read = total_bytes_to_read - _data_buffer.tell()
        return _data_buffer.getvalue()

    def read(self, b=None):
        # type: (Optional[int]) -> bytes
        """Read bytes from wrapped stream, base64-decoding before return, and adjusting read
        from wrapped stream to return correct number of bytes.

        :param int b: Number of bytes to read
        :returns: Decoded bytes from wrapped stream
        :rtype: bytes
        """
        if self.closed:
            raise ValueError('I/O operation on closed file.')

        if not self.readable():
            raise IOError('Stream is not readable')

        if b is not None and b < 0:
            b = None
        _bytes_to_read = None
        if b is not None:
            # Calculate number of encoded bytes that must be read to get b raw bytes.
            _bytes_to_read = int((b - len(self.__read_buffer)) * 4 / 3)
            _bytes_to_read += (4 - _bytes_to_read % 4)

        # Read encoded bytes from wrapped stream.
        data = self.__wrapped.read(_bytes_to_read)
        # Remove whitespace from read data and attempt to read more data to get the desired
        # number of bytes.
        if any([six.b(char) in data for char in string.whitespace]):
            data = self._read_additional_data_removing_whitespace(data, _bytes_to_read)

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

    def __iter__(self):  # type: ignore
        # Until https://github.com/python/typing/issues/11
        # there's no good way to tell mypy about custom
        # iterators that subclass io.IOBase.
        """Let this class act as an iterator."""
        return self

    def readline(self, limit=-1):
        # type: (int) -> bytes
        """Read and return one line from the stream.
        If limit is specified, at most limit bytes will be read.

        .. note::

            Because the source that this reads from may not contain any OEL characters, we
            read "lines" in chunks of length ``io.DEFAULT_BUFFER_SIZE``.

        :type limit: int
        :rtype: bytes
        """
        return self.read(limit if limit > 0 else io.DEFAULT_BUFFER_SIZE)

    def readlines(self, hint=-1):
        # type: (int) -> List[bytes]
        """Read and return a list of lines from the stream. hint can be specified to control
        the number of lines read: no more lines will be read if the total size (in bytes/
        characters) of all lines so far exceeds hint.

        :type hint: int
        :returns: Lines of data
        :rtype: list of bytes
        """
        lines = []
        for line in self:  # type: ignore
            lines.append(line)
            if hint > 0 and len(lines) * io.DEFAULT_BUFFER_SIZE > hint:
                break
        return lines

    def __next__(self):
        # type: () -> bytes
        """Python 3 iterator hook."""
        line = self.readline()
        if line:
            return line
        raise StopIteration()

    def next(self):
        # type: () -> bytes
        """Python 2 iterator hook."""
        return self.__next__()
