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
"""Unit test suite for ``aws_encryption_sdk_cli.internal.metadata``."""
import json
import os

import pytest

from aws_encryption_sdk_cli.internal import metadata

GOOD_INIT_KWARGS = dict(
    suppress_output=False,
    output_mode='w'
)


@pytest.mark.parametrize('init_kwargs, call_kwargs', (
    (dict(suppress_output=True), dict()),
    (dict(suppress_output=False, output_mode='w'), dict(output_file='-')),
    (dict(suppress_output=False, output_mode='w'), dict(output_file='asdf')),
    (dict(suppress_output=False, output_mode='a'), dict(output_file='asdf'))
))
def test_attrs_good(init_kwargs, call_kwargs):
    metadata.MetadataWriter(**init_kwargs)(**call_kwargs)


@pytest.mark.parametrize('init_kwargs_patch, error_type', (
    (dict(suppress_output='not a bool'), TypeError),
    (dict(output_mode='u3982u'), ValueError)
))
def test_attrs_fail(init_kwargs_patch, error_type):
    """Verifying that validators are applied because we overwrite attrs init."""
    init_kwargs = GOOD_INIT_KWARGS.copy()
    init_kwargs.update(init_kwargs_patch)

    with pytest.raises(error_type):
        metadata.MetadataWriter(**init_kwargs)()


@pytest.mark.parametrize('init_kwargs, call_kwargs, error_type, error_message', (
    (
        dict(suppress_output=False),
        dict(),
        TypeError,
        r'output_mode cannot be None when suppress_output is False'
    ),
    (
        dict(suppress_output=False, output_mode='w'),
        dict(),
        TypeError,
        r'output_file cannot be None when suppress_output is False'
    ),
    (
        dict(suppress_output=False, output_mode='a'),
        dict(output_file='-'),
        ValueError,
        r'output_mode must be "w" when output_file is stdout'
    )
))
def test_custom_fail(init_kwargs, call_kwargs, error_type, error_message):
    with pytest.raises(error_type) as excinfo:
        metadata.MetadataWriter(**init_kwargs)(**call_kwargs)

    excinfo.match(error_message)


@pytest.mark.parametrize('suppress', (True, False))
def test_write_or_suppress_metadata_stdout(capsys, suppress):
    my_metadata = {
        'some': 'data',
        'for': 'this metadata'
    }
    writer_factory = metadata.MetadataWriter(suppress_output=suppress, output_mode='w')
    writer = writer_factory('-')

    with writer:
        writer.write_metadata(**my_metadata)

    out, _err = capsys.readouterr()
    if suppress:
        assert out == ''
    else:
        assert json.loads(out) == my_metadata


@pytest.mark.parametrize('suppress', (True, False))
def test_write_or_suppress_metadata_file(tmpdir, suppress):
    my_metadata = {
        'some': 'data',
        'for': 'this metadata'
    }
    output_file = tmpdir.join('metadata')
    writer_factory = metadata.MetadataWriter(suppress_output=suppress, output_mode='w')
    writer = writer_factory(str(output_file))

    with writer:
        writer.write_metadata(**my_metadata)

    if suppress:
        assert not output_file.isfile()
    else:
        assert json.loads(output_file.read()) == my_metadata


def test_write_or_suppress_metadata_file_open_close(tmpdir):
    my_metadata = {
        'some': 'data',
        'for': 'this metadata'
    }
    output_file = tmpdir.join('metadata')
    writer_factory = metadata.MetadataWriter(suppress_output=False, output_mode='w')
    writer = writer_factory(str(output_file))

    writer.open()
    try:
        writer.write_metadata(**my_metadata)
    finally:
        writer.close()

    assert json.loads(output_file.read()) == my_metadata


def test_append_metadata_file(tmpdir):
    initial_data = 'some data'
    my_metadata = {
        'some': 'data',
        'for': 'this metadata'
    }
    output_file = tmpdir.join('metadata')
    output_file.write(initial_data + os.linesep)

    writer_factory = metadata.MetadataWriter(suppress_output=False, output_mode='a')
    writer = writer_factory(str(output_file))

    with writer:
        writer.write_metadata(**my_metadata)

    lines = output_file.readlines()
    assert len(lines) == 2
    assert lines[0].strip() == initial_data
    assert json.loads(lines[1].strip()) == my_metadata
