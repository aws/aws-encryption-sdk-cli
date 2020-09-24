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
# remove once this is resolved https://github.com/PyCQA/pylint/issues/2313
# pylint: disable=no-name-in-module,import-error
import json
import os

import pytest
from aws_encryption_sdk.identifiers import Algorithm, ContentType, ObjectType, SerializationVersion
from aws_encryption_sdk.internal.structures import MessageHeaderAuthentication
from aws_encryption_sdk.structures import EncryptedDataKey, MasterKeyInfo, MessageHeader

from aws_encryption_sdk_cli.exceptions import BadUserArgumentError
from aws_encryption_sdk_cli.internal import metadata

pytestmark = [pytest.mark.unit, pytest.mark.local]
GOOD_INIT_KWARGS = dict(suppress_output=False)


@pytest.mark.parametrize(
    "init_kwargs, call_kwargs",
    (
        (dict(suppress_output=True), dict()),
        (dict(suppress_output=False), dict(output_file="-")),
        (dict(suppress_output=False), dict(output_file="asdf")),
    ),
)
def test_attrs_good(init_kwargs, call_kwargs):
    metadata.MetadataWriter(**init_kwargs)(**call_kwargs)


@pytest.mark.parametrize("init_kwargs_patch, error_type", ((dict(suppress_output=None), TypeError),))
def test_attrs_fail(init_kwargs_patch, error_type):
    """Verifying that validators are applied because we overwrite attrs init."""
    init_kwargs = GOOD_INIT_KWARGS.copy()
    init_kwargs.update(init_kwargs_patch)

    with pytest.raises(error_type):
        metadata.MetadataWriter(**init_kwargs)()


@pytest.mark.parametrize(
    "init_kwargs, call_kwargs, error_type, error_message",
    ((dict(suppress_output=False), dict(), TypeError, r"output_file cannot be None when suppress_output is False"),),
)
def test_custom_fail(init_kwargs, call_kwargs, error_type, error_message):
    with pytest.raises(error_type) as excinfo:
        metadata.MetadataWriter(**init_kwargs)(**call_kwargs)

    excinfo.match(error_message)


@pytest.mark.parametrize(
    "filename, force_overwrite, expected_mode",
    (("a_file", False, "ab"), ("-", False, "w"), ("a_file", True, "wb"), ("-", True, "wb")),
)
def test_write_metadata_default_output_modes(filename, force_overwrite, expected_mode):
    test = metadata.MetadataWriter(suppress_output=False)(filename)
    if force_overwrite:
        test.force_overwrite()

    assert test._output_mode == expected_mode


@pytest.mark.parametrize("suppress", (True, False))
def test_write_or_suppress_metadata_stdout(capsys, suppress):
    my_metadata = {"some": "data", "for": "this metadata"}
    writer_factory = metadata.MetadataWriter(suppress_output=suppress)
    writer = writer_factory("-")

    with writer:
        writer.write_metadata(**my_metadata)

    out, _err = capsys.readouterr()
    if suppress:
        assert out == ""
    else:
        assert json.loads(out) == my_metadata


@pytest.mark.parametrize("suppress", (True, False))
def test_write_or_suppress_metadata_file(tmpdir, suppress):
    my_metadata = {"some": "data", "for": "this metadata"}
    output_file = tmpdir.join("metadata")
    writer_factory = metadata.MetadataWriter(suppress_output=suppress)
    writer = writer_factory(str(output_file))

    with writer:
        writer.write_metadata(**my_metadata)

    if suppress:
        assert not output_file.isfile()
    else:
        assert json.loads(output_file.read()) == my_metadata


def test_write_or_suppress_metadata_file_open_close(tmpdir):
    my_metadata = {"some": "data", "for": "this metadata"}
    output_file = tmpdir.join("metadata")
    writer_factory = metadata.MetadataWriter(suppress_output=False)
    writer = writer_factory(str(output_file))

    writer.open()
    try:
        writer.write_metadata(**my_metadata)
    finally:
        writer.close()

    assert json.loads(output_file.read()) == my_metadata


def test_append_metadata_file(tmpdir):
    initial_data = "some data"
    my_metadata = {"some": "data", "for": "this metadata"}
    output_file = tmpdir.join("metadata")
    output_file.write_binary((initial_data + os.linesep).encode("utf-8"))

    with metadata.MetadataWriter(suppress_output=False)(str(output_file)) as writer:
        writer.write_metadata(**my_metadata)

    lines = output_file.readlines()
    assert len(lines) == 2
    assert lines[0].strip() == initial_data
    assert json.loads(lines[1].strip()) == my_metadata


def test_overwrite_metdata_file(tmpdir):
    initial_data = "some data"
    my_metadata = {"some": "data", "for": "this metadata"}
    output_file = tmpdir.join("metadata")
    output_file.write(initial_data + os.linesep)

    overwrite_writer = metadata.MetadataWriter(suppress_output=False)(str(output_file))
    overwrite_writer.force_overwrite()

    with overwrite_writer as writer:
        writer.write_metadata(**my_metadata)

    lines = output_file.readlines()
    assert len(lines) == 1
    assert json.loads(lines[0].strip()) == my_metadata


def test_overwrite_metdata_file_multiuse(tmpdir):
    initial_data = "some data"
    my_metadata = {"some": "data", "for": "this metadata"}
    output_file = tmpdir.join("metadata")
    output_file.write(initial_data + os.linesep)

    long_lived_writer = metadata.MetadataWriter(suppress_output=False)(str(output_file))
    long_lived_writer.force_overwrite()

    assert long_lived_writer._output_mode == "wb"

    with long_lived_writer as writer:
        writer.write_metadata(**my_metadata)

    assert long_lived_writer._output_mode == "ab"

    with long_lived_writer as writer:
        writer.write_metadata(**my_metadata)

    lines = output_file.readlines()
    assert len(lines) == 2
    assert json.loads(lines[0].strip()) == my_metadata
    assert lines[0] == lines[1]


def test_metadata_output_file_parent_dir_does_not_exist(tmpdir):
    metadata_file = os.path.join(str(tmpdir), "missing_dir", "metadata")

    with pytest.raises(BadUserArgumentError) as excinfo:
        metadata.MetadataWriter(suppress_output=False)(metadata_file)

    excinfo.match(r"Parent directory for requested metdata file does not exist.")


def test_json_ready_message_header():
    # pylint: disable=too-many-locals
    message_id = b"a message ID"
    encryption_context = {"a": "b", "c": "d"}
    content_aad_length = 8
    iv_length = 17
    frame_length = 99
    master_key_provider_id_1 = b"provider 1"
    master_key_provider_info_1 = b"master key 1"
    encrypted_data_key_1 = b"an encrypted data key1"
    master_key_provider_id_2 = b"provider 1"
    master_key_provider_info_2 = b"master key 2"
    encrypted_data_key_2 = b"an encrypted data key2"
    master_key_provider_id_3 = b"another provider"
    master_key_provider_info_3 = b"master key 3"
    encrypted_data_key_3 = b"an encrypted data key3"
    raw_header = MessageHeader(
        version=SerializationVersion.V1,
        type=ObjectType.CUSTOMER_AE_DATA,
        algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
        message_id=message_id,
        encryption_context=encryption_context,
        encrypted_data_keys=set(
            [
                EncryptedDataKey(
                    key_provider=MasterKeyInfo(
                        provider_id=master_key_provider_id_1, key_info=master_key_provider_info_1
                    ),
                    encrypted_data_key=encrypted_data_key_1,
                ),
                EncryptedDataKey(
                    key_provider=MasterKeyInfo(
                        provider_id=master_key_provider_id_2, key_info=master_key_provider_info_2
                    ),
                    encrypted_data_key=encrypted_data_key_2,
                ),
                EncryptedDataKey(
                    key_provider=MasterKeyInfo(
                        provider_id=master_key_provider_id_3, key_info=master_key_provider_info_3
                    ),
                    encrypted_data_key=encrypted_data_key_3,
                ),
            ]
        ),
        content_type=ContentType.FRAMED_DATA,
        content_aad_length=content_aad_length,
        header_iv_length=iv_length,
        frame_length=frame_length,
    )
    expected_header_dict = {
        "version": "1.0",
        "type": ObjectType.CUSTOMER_AE_DATA.value,
        "commitment_key": None,
        "algorithm": Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384.name,
        "message_id": metadata.unicode_b64_encode(message_id),
        "encryption_context": encryption_context,
        "encrypted_data_keys": [
            {
                "key_provider": {
                    "provider_id": metadata.unicode_b64_encode(master_key_provider_id_3),
                    "key_info": metadata.unicode_b64_encode(master_key_provider_info_3),
                },
                "encrypted_data_key": metadata.unicode_b64_encode(encrypted_data_key_3),
            },
            {
                "key_provider": {
                    "provider_id": metadata.unicode_b64_encode(master_key_provider_id_1),
                    "key_info": metadata.unicode_b64_encode(master_key_provider_info_1),
                },
                "encrypted_data_key": metadata.unicode_b64_encode(encrypted_data_key_1),
            },
            {
                "key_provider": {
                    "provider_id": metadata.unicode_b64_encode(master_key_provider_id_2),
                    "key_info": metadata.unicode_b64_encode(master_key_provider_info_2),
                },
                "encrypted_data_key": metadata.unicode_b64_encode(encrypted_data_key_2),
            },
        ],
        "content_type": ContentType.FRAMED_DATA.value,
        "header_iv_length": iv_length,
        "frame_length": frame_length,
    }

    test = metadata.json_ready_header(raw_header)

    assert test == expected_header_dict
    # verify that the dict is actually JSON-encodable
    json.dumps(test)


def test_json_ready_header_auth():
    iv = b"some random bytes"
    tag = b"some not random bytes"
    raw_header_auth = MessageHeaderAuthentication(iv=iv, tag=tag)
    expected_header_auth_dict = {"iv": metadata.unicode_b64_encode(iv), "tag": metadata.unicode_b64_encode(tag)}

    test = metadata.json_ready_header_auth(raw_header_auth)

    assert test == expected_header_auth_dict
    # verify that the dict is actually JSON-encodable
    json.dumps(test)
