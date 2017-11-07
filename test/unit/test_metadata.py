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

import pytest
import six

from aws_encryption_sdk_cli.internal import metadata


def test_attrs_callthrough():
    """Verifying that validators are applied because we overwrite attrs init."""
    with pytest.raises(TypeError):
        metadata.MetadataWriter(suppress_output='not a bool')


def test_metadata_writer_no_output_stream():
    with pytest.raises(AttributeError) as excinfo:
        metadata.MetadataWriter(suppress_output=False)

    excinfo.match(r'output_stream must be specified when suppress_output is False.')


def test_metadata_writer_bad_output_stream():
    with pytest.raises(AttributeError) as excinfo:
        metadata.MetadataWriter(suppress_output=False, output_stream=5)

    excinfo.match(r'Metadata output stream must have "write" method.')


def test_metadata_writer_write_metadata():
    output = six.StringIO()
    my_metadata = {
        'some': 'data',
        'for': 'this metadata'
    }
    writer = metadata.MetadataWriter(suppress_output=False, output_stream=output)

    writer.write_metadata(**my_metadata)

    raw_metadata = output.getvalue()
    assert json.loads(raw_metadata) == my_metadata


def test_metadata_writer_suppress_metadata():
    output = six.StringIO()
    my_metadata = {
        'some': 'data',
        'for': 'this metadata'
    }
    writer = metadata.MetadataWriter(suppress_output=True, output_stream=output)

    writer.write_metadata(**my_metadata)

    assert output.getvalue() == ''
