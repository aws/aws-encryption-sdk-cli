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
"""Unit test suite for ``aws_encryption_sdk_cli.internal.encoding``."""
import base64
import functools
import io
import os

from mock import MagicMock, sentinel
import pytest

from aws_encryption_sdk_cli.internal.encoding import Base64IO

pytestmark = [pytest.mark.unit, pytest.mark.local]


def test_base64io_bad_wrap():
    with pytest.raises(TypeError) as excinfo:
        Base64IO(7)

    excinfo.match(r'Base64IO wrapped object must have attributes: *')


def test_base64io_write_after_closed():
    with Base64IO(io.BytesIO()) as test:
        with pytest.raises(ValueError) as excinfo:
            test.close()
            test.write(b'aksdhjf')

    excinfo.match(r'I/O operation on closed file.')


def test_base64io_read_after_closed():
    with Base64IO(io.BytesIO()) as test:
        with pytest.raises(ValueError) as excinfo:
            test.close()
            test.read()

    excinfo.match(r'I/O operation on closed file.')


@pytest.mark.parametrize('method_name', ('isatty', 'seekable'))
def test_base64io_always_false_methods(method_name):
    test = Base64IO(io.BytesIO())

    assert not getattr(test, method_name)()


@pytest.mark.parametrize('method_name', ('fileno', 'seek', 'tell', 'truncate'))
def test_unsupported_methods(method_name):
    test = Base64IO(io.BytesIO())

    with pytest.raises(IOError):
        getattr(test, method_name)()


@pytest.mark.parametrize('method_name', ('flush', 'writable', 'readable'))
def test_passthrough_methods_present(monkeypatch, method_name):
    wrapped = io.BytesIO()
    monkeypatch.setattr(wrapped, method_name, lambda: sentinel.passthrough)
    wrapper = Base64IO(wrapped)

    assert getattr(wrapper, method_name)() is sentinel.passthrough


@pytest.mark.parametrize('method_name', ('writable', 'readable'))
def test_passthrough_methods_not_present(monkeypatch, method_name):
    wrapped = MagicMock()
    monkeypatch.delattr(wrapped, method_name, False)
    wrapper = Base64IO(wrapped)

    assert not getattr(wrapper, method_name)()


@pytest.mark.parametrize('mode, method_name, expected', (
    ('wb', 'writable', True),
    ('rb', 'readable', True),
    ('rb', 'writable', False),
    ('wb', 'readable', False)
))
def test_passthrough_methods_file(tmpdir, method_name, mode, expected):
    source = tmpdir.join('source')
    source.write('some data')

    with open(str(source), mode) as reader:
        with Base64IO(reader) as b64:
            test = getattr(b64, method_name)()

    if expected:
        assert test
    else:
        assert not test


@pytest.mark.parametrize('patch_method, call_method, call_arg', (
    ('writable', 'write', b''),
    ('readable', 'read', 0)
))
def test_non_interactive_error(monkeypatch, patch_method, call_method, call_arg):
    wrapped = io.BytesIO()
    monkeypatch.setattr(wrapped, patch_method, lambda: False)

    with Base64IO(wrapped) as wrapper:
        with pytest.raises(IOError) as excinfo:
            getattr(wrapper, call_method)(call_arg)

    excinfo.match(r'Stream is not ' + patch_method)


def build_test_cases():
    """Build test cases for read/write encoding checks.

    :returns: (bytes_to_generate, bytes_per_round, number_of_rounds, total_bytes_to_expect)
    """
    test_cases = []

    # exact single-shot, varying multiples
    for size in (1, 2, 3, 4, 5, 6, 7, 222, 1024):
        test_cases.append((size, size, 1, size))

    test_cases.append((1024, None, 1, 1024))  # single-shot
    test_cases.append((1024, -1, 1, 1024))  # single-shot

    # Odd multiples with operation smaller, equal to, and larger than total
    for rounds in (1, 3, 5):
        for read_size in (1, 2, 3, 4, 5, 1024, 1500):
            test_cases.append((1024, read_size, rounds, min(read_size * rounds, 1024)))

    return test_cases


@pytest.mark.parametrize(
    'bytes_to_generate, bytes_per_round, number_of_rounds, total_bytes_to_expect',
    build_test_cases()
)
def test_base64io_decode(bytes_to_generate, bytes_per_round, number_of_rounds, total_bytes_to_expect):
    plaintext_source = os.urandom(bytes_to_generate)
    plaintext_b64 = io.BytesIO(base64.b64encode(plaintext_source))
    plaintext_wrapped = Base64IO(plaintext_b64)

    test = b''
    for _round in range(number_of_rounds):
        test += plaintext_wrapped.read(bytes_per_round)

    assert len(test) == total_bytes_to_expect
    assert test == plaintext_source[:total_bytes_to_expect]


@pytest.mark.parametrize('source_bytes', [case[0] for case in build_test_cases()])
def test_base64io_encode_context_manager(source_bytes):
    plaintext_source = os.urandom(source_bytes)
    plaintext_b64 = base64.b64encode(plaintext_source)
    plaintext_stream = io.BytesIO()

    with Base64IO(plaintext_stream) as plaintext_wrapped:
        plaintext_wrapped.write(plaintext_source)

    assert plaintext_stream.getvalue() == plaintext_b64


def test_base64io_encode_context_manager_reuse():
    plaintext_source = os.urandom(10)
    plaintext_stream = io.BytesIO()

    stream = Base64IO(plaintext_stream)

    with stream as plaintext_wrapped:
        plaintext_wrapped.write(plaintext_source)

    with pytest.raises(ValueError) as excinfo:
        with stream as plaintext_wrapped:
            plaintext_wrapped.read()

    excinfo.match(r'I/O operation on closed file.')


def test_base64io_encode_use_after_context_manager_exit():
    plaintext_source = os.urandom(10)
    plaintext_stream = io.BytesIO()

    stream = Base64IO(plaintext_stream)

    with stream as plaintext_wrapped:
        plaintext_wrapped.write(plaintext_source)

    assert stream.closed

    with pytest.raises(ValueError) as excinfo:
        stream.read()

    excinfo.match(r'I/O operation on closed file.')


@pytest.mark.parametrize('source_bytes', [case[0] for case in build_test_cases()])
def test_base64io_encode(source_bytes):
    plaintext_source = os.urandom(source_bytes)
    plaintext_b64 = base64.b64encode(plaintext_source)
    plaintext_stream = io.BytesIO()

    plaintext_wrapped = Base64IO(plaintext_stream)
    try:
        plaintext_wrapped.write(plaintext_source)
    finally:
        plaintext_wrapped.close()

    assert plaintext_stream.getvalue() == plaintext_b64


@pytest.mark.parametrize('bytes_to_read, expected_bytes_read', (
    (-1, io.DEFAULT_BUFFER_SIZE),
    (0, io.DEFAULT_BUFFER_SIZE),
    (1, 1),
    (10, 10)
))
def test_base64io_decode_readline(bytes_to_read, expected_bytes_read):
    source_plaintext = os.urandom(io.DEFAULT_BUFFER_SIZE * 2)
    source_stream = io.BytesIO(base64.b64encode(source_plaintext))

    with Base64IO(source_stream) as decoder:
        test = decoder.readline(bytes_to_read)

    assert test == source_plaintext[:expected_bytes_read]


def build_b64_with_whitespace(source_bytes, line_length):
    plaintext_source = os.urandom(source_bytes)
    b64_plaintext = io.BytesIO(base64.b64encode(plaintext_source))
    b64_plaintext_with_whitespace = b'\n'.join([
        line for line
        in iter(functools.partial(b64_plaintext.read, line_length), b'')
    ])
    return plaintext_source, b64_plaintext_with_whitespace


def build_whitespace_testcases():
    scenarios = []
    for test_case in build_test_cases():
        scenarios.append(build_b64_with_whitespace(test_case[0], 3) + (test_case[-1],))

    # first read is mostly whitespace
    plaintext, b64_plaintext = build_b64_with_whitespace(100, 20)
    b64_plaintext = (b' ' * 80) + b64_plaintext
    scenarios.append((plaintext, b64_plaintext, 100))

    # first several reads are entirely whitespace
    plaintext, b64_plaintext = build_b64_with_whitespace(100, 20)
    b64_plaintext = (b' ' * 500) + b64_plaintext
    scenarios.append((plaintext, b64_plaintext, 100))

    return scenarios


@pytest.mark.parametrize('plaintext_source, b64_plaintext_with_whitespace, read_bytes', build_whitespace_testcases())
def test_base64io_decode_with_whitespace(plaintext_source, b64_plaintext_with_whitespace, read_bytes):
    with Base64IO(io.BytesIO(b64_plaintext_with_whitespace)) as decoder:
        test = decoder.read(read_bytes)

    assert test == plaintext_source[:read_bytes]


@pytest.mark.parametrize('plaintext_source, b64_plaintext_with_whitespace, read_bytes', (
    (b'\x00\x00\x00', b'AAAA', 3),
))
def test_base64io_decode_parametrized_null_bytes(plaintext_source, b64_plaintext_with_whitespace, read_bytes):
    # Verifies that pytest is handling null bytes correctly (broken in 3.3.0)
    # https://github.com/pytest-dev/pytest/issues/2957
    with Base64IO(io.BytesIO(b64_plaintext_with_whitespace)) as decoder:
        test = decoder.read(read_bytes)

    assert test == plaintext_source[:read_bytes]


def test_base64io_decode_read_only_from_buffer():
    plaintext_source = b'12345'
    plaintext_b64 = io.BytesIO(base64.b64encode(plaintext_source))
    plaintext_wrapped = Base64IO(plaintext_b64)

    test_1 = plaintext_wrapped.read(1)
    test_2 = plaintext_wrapped.read(1)
    test_3 = plaintext_wrapped.read()

    assert test_1 == b'1'
    assert test_2 == b'2'
    assert test_3 == b'345'


def test_base64io_decode_context_manager():
    source_plaintext = os.urandom(102400)
    source_stream = io.BytesIO(base64.b64encode(source_plaintext))

    test = io.BytesIO()
    with Base64IO(source_stream) as stream:
        for chunk in stream:
            test.write(chunk)

    assert test.getvalue() == source_plaintext
    assert not source_stream.closed


def test_base64io_decode_context_manager_close_source():
    source_plaintext = os.urandom(102400)
    source_stream = io.BytesIO(base64.b64encode(source_plaintext))

    test = io.BytesIO()
    with Base64IO(source_stream, close_wrapped_on_close=True) as stream:
        for chunk in stream:
            test.write(chunk)

    assert test.getvalue() == source_plaintext
    assert source_stream.closed


@pytest.mark.parametrize('hint_bytes, expected_bytes_read', (
    (-1, 102400),
    (0, 102400),
    (1, io.DEFAULT_BUFFER_SIZE),
    (io.DEFAULT_BUFFER_SIZE + 99, io.DEFAULT_BUFFER_SIZE * 2)
))
def test_base64io_decode_readlines(hint_bytes, expected_bytes_read):
    source_plaintext = os.urandom(102400)
    source_stream = io.BytesIO(base64.b64encode(source_plaintext))

    test = io.BytesIO()
    with Base64IO(source_stream) as stream:
        for chunk in stream.readlines(hint_bytes):
            test.write(chunk)

    assert len(test.getvalue()) == expected_bytes_read
    assert test.getvalue() == source_plaintext[:expected_bytes_read]


def test_base64io_encode_writelines():
    source_plaintext = [os.urandom(1024) for _ in range(100)]
    b64_plaintext = base64.b64encode(b''.join(source_plaintext))

    test = io.BytesIO()
    with Base64IO(test) as encoder:
        encoder.writelines(source_plaintext)

    assert test.getvalue() == b64_plaintext


def test_base64io_decode_file(tmpdir):
    source_plaintext = os.urandom(1024 * 1024)
    b64_plaintext = tmpdir.join('base64_plaintext')
    b64_plaintext.write(base64.b64encode(source_plaintext))
    decoded_plaintext = tmpdir.join('decoded_plaintext')

    with open(str(b64_plaintext), 'rb') as source, open(str(decoded_plaintext), 'wb') as raw:
        with Base64IO(source) as decoder:
            for chunk in decoder:
                raw.write(chunk)

    with open(str(decoded_plaintext), 'rb') as raw:
        decoded = raw.read()

    assert decoded == source_plaintext


def test_base64io_encode_file(tmpdir):
    source_plaintext = os.urandom(1024 * 1024)
    plaintext_b64 = base64.b64encode(source_plaintext)
    plaintext = tmpdir.join('plaintext')
    b64_plaintext = tmpdir.join('base64_plaintext')

    with open(str(plaintext), 'wb') as file:
        file.write(source_plaintext)

    with open(str(plaintext), 'rb') as source, open(str(b64_plaintext), 'wb') as target:
        with Base64IO(target) as encoder:
            for chunk in source:
                encoder.write(chunk)

    with open(str(b64_plaintext), 'rb') as file2:
        encoded = file2.read()

    assert encoded == plaintext_b64
