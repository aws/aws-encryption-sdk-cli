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
"""Unit test suite for ``aws_encryption_sdk_cli.internal.master_key_parsing``."""
import logging
from collections import defaultdict, namedtuple

import pytest
import six
from mock import MagicMock, call, sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

from aws_encryption_sdk_cli.exceptions import BadUserArgumentError
from aws_encryption_sdk_cli.internal import logging_utils, master_key_parsing
from aws_encryption_sdk_cli.key_providers import aws_kms_master_key_provider

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def patch_load_master_key_provider(mocker):
    mocker.patch.object(master_key_parsing, "_load_master_key_provider")
    yield master_key_parsing._load_master_key_provider


@pytest.fixture
def patch_build_master_key_provider(mocker):
    mocker.patch.object(master_key_parsing, "_build_master_key_provider")
    master_key_parsing._build_master_key_provider.side_effect = (sentinel.key_provider_1, sentinel.key_provider_2)
    yield master_key_parsing._build_master_key_provider


@pytest.fixture
def patch_assemble_master_key_providers(mocker):
    mocker.patch.object(master_key_parsing, "_assemble_master_key_providers")
    master_key_parsing._assemble_master_key_providers.return_value = sentinel.assembled_key_providers
    yield master_key_parsing._assemble_master_key_providers


@pytest.fixture
def patch_parse_master_key_providers(mocker):
    mocker.patch.object(master_key_parsing, "_parse_master_key_providers_from_args")
    yield master_key_parsing._parse_master_key_providers_from_args


@pytest.fixture
def patch_aws_encryption_sdk(mocker):
    mocker.patch.object(master_key_parsing, "aws_encryption_sdk")
    yield master_key_parsing.aws_encryption_sdk


@pytest.fixture
def patch_iter_entry_points(mocker):
    mocker.patch.object(master_key_parsing.pkg_resources, "iter_entry_points")
    yield master_key_parsing.pkg_resources.iter_entry_points


@pytest.fixture
def logger_stream():
    output_stream = six.StringIO()
    formatter = logging.Formatter(logging_utils.FORMAT_STRING)
    handler = logging.StreamHandler(stream=output_stream)
    handler.setFormatter(formatter)
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    return output_stream


@pytest.fixture
def entry_points_cleaner():
    master_key_parsing._ENTRY_POINTS = defaultdict(dict)
    yield
    master_key_parsing._ENTRY_POINTS = defaultdict(dict)


# "name" is a special, non-overridable attribute on mock objects
FakeEntryPoint = namedtuple("FakeEntryPoint", ["name", "module_name", "attrs", "extras", "dist"])
FakeEntryPoint.__new__.__defaults__ = ("MODULE", "ATTRS", "EXTRAS", MagicMock(project_name="PROJECT"))


def test_entry_points(monkeypatch):
    monkeypatch.setattr(master_key_parsing, "_ENTRY_POINTS", defaultdict(dict))
    test = master_key_parsing._entry_points()

    assert test == master_key_parsing._ENTRY_POINTS


def test_entry_points_aws_kms():
    assert master_key_parsing._entry_points()["aws-kms"]["aws-encryption-sdk-cli"].load() is aws_kms_master_key_provider


def test_entry_points_invalid_substring(logger_stream, patch_iter_entry_points):
    patch_iter_entry_points.return_value = [FakeEntryPoint("BAD::NAME")]
    master_key_parsing._discover_entry_points()

    key = 'Invalid substring "::" in discovered entry point "BAD::NAME". It will not be usable.'
    logging_results = logger_stream.getvalue()
    assert key in logging_results
    assert "BAD::NAME" not in master_key_parsing._ENTRY_POINTS


def test_entry_points_multiple_per_name(entry_points_cleaner, patch_iter_entry_points):
    entry_point_a = FakeEntryPoint(name="aws-kms", dist=MagicMock(project_name="aws-encryption-sdk-cli"))
    entry_point_b = FakeEntryPoint(name="aws-kms", dist=MagicMock(project_name="some-other-thing"))
    entry_point_c = FakeEntryPoint(name="zzz", dist=MagicMock(project_name="yet-another-thing"))
    patch_iter_entry_points.return_value = [entry_point_a, entry_point_b, entry_point_c]

    test = master_key_parsing._entry_points()

    assert dict(test) == {
        "aws-kms": {"aws-encryption-sdk-cli": entry_point_a, "some-other-thing": entry_point_b},
        "zzz": {"yet-another-thing": entry_point_c},
    }


def test_load_master_key_provider_unknown_name(monkeypatch):
    master_key_parsing._entry_points()
    monkeypatch.setattr(master_key_parsing, "_ENTRY_POINTS", defaultdict(dict))
    with pytest.raises(BadUserArgumentError) as excinfo:
        master_key_parsing._load_master_key_provider("unknown_name")

    excinfo.match(r'Requested master key provider not found: "unknown_name"')


def test_load_master_key_provider_known_name_only_single_entry_point():
    assert master_key_parsing._load_master_key_provider("aws-kms") is aws_kms_master_key_provider


def test_load_master_key_provider_known_name_only_multiple_entry_points(monkeypatch):
    monkeypatch.setitem(
        master_key_parsing._ENTRY_POINTS,
        "aws-kms",
        {
            "aws-encryption-sdk-cli": FakeEntryPoint(
                name="aws-kms", dist=MagicMock(project_name="aws-encryption-sdk-cli")
            ),
            "my-fake-package": FakeEntryPoint(name="aws-kms", module_name="my-fake-package"),
        },
    )

    with pytest.raises(BadUserArgumentError) as excinfo:
        master_key_parsing._load_master_key_provider("aws-kms")

    excinfo.match(r"Multiple entry points discovered and no package specified. *")


def test_load_master_key_provider_known_package_and_name():
    assert (
        master_key_parsing._load_master_key_provider("aws-encryption-sdk-cli::aws-kms") is aws_kms_master_key_provider
    )


def test_load_master_key_provider_known_name_unknown_name(monkeypatch):
    monkeypatch.setitem(
        master_key_parsing._ENTRY_POINTS,
        "aws-kms",
        {"my-fake-package": FakeEntryPoint(name="aws-kms", module_name="my-fake-package")},
    )

    with pytest.raises(BadUserArgumentError) as excinfo:
        master_key_parsing._load_master_key_provider("aws-encryption-sdk-cli::aws-kms")

    excinfo.match(
        r'Requested master key provider not found: "aws-encryption-sdk-cli::aws-kms". Packages discovered for *'
    )


def test_build_master_key_provider_known_provider(patch_load_master_key_provider):
    mock_provider_callable = MagicMock()
    patch_load_master_key_provider.return_value = mock_provider_callable
    test = master_key_parsing._build_master_key_provider(
        discovery=sentinel.discovery, provider=sentinel.known_provider_id, key=[], a=sentinel.a, b=sentinel.b
    )
    patch_load_master_key_provider.assert_called_once_with(sentinel.known_provider_id)
    mock_provider_callable.assert_called_once_with(a=sentinel.a, b=sentinel.b, discovery=sentinel.discovery)
    assert not mock_provider_callable.return_value.add_master_key.called
    assert test is mock_provider_callable.return_value


def test_build_master_key_provider_add_keys(patch_load_master_key_provider):
    mock_provider = MagicMock()
    patch_load_master_key_provider.return_value.return_value = mock_provider
    master_key_parsing._build_master_key_provider(
        discovery=True, provider=sentinel.unknown_provider_id, key=[sentinel.key_id_1, sentinel.key_id_2]
    )
    mock_provider.add_master_key.assert_has_calls(
        calls=(call(sentinel.key_id_1), call(sentinel.key_id_2)), any_order=False
    )


def test_build_master_key_provider_additional_kwargs(patch_load_master_key_provider):
    kwargs = {"a": 1, "b": "asdf", "discovery": True}
    master_key_parsing._build_master_key_provider(provider=sentinel.unknown_provider_id, key=[], **kwargs)
    patch_load_master_key_provider.return_value.assert_called_once_with(**kwargs)


def test_assemble_master_key_providers():
    mock_primary = MagicMock()
    test = master_key_parsing._assemble_master_key_providers(mock_primary, sentinel.provider_1, sentinel.provider_2)
    mock_primary.add_master_key_provider.assert_has_calls(
        calls=(call(sentinel.provider_1), call(sentinel.provider_2)), any_order=False
    )
    assert test is mock_primary


def test_parse_master_key_providers_from_args(patch_build_master_key_provider, patch_assemble_master_key_providers):
    test = master_key_parsing._parse_master_key_providers_from_args(
        {"provider": "provider_1_a", "key": ["provider_info_1_b"]},
        {"provider": "provider_2_a", "key": ["provider_info_2_b"], "z": "additional_z"},
    )
    patch_build_master_key_provider.assert_has_calls(
        calls=(
            call(provider="provider_1_a", key=["provider_info_1_b"], key_ids=["provider_info_1_b"]),
            call(provider="provider_2_a", key=["provider_info_2_b"], z="additional_z", key_ids=["provider_info_2_b"]),
        ),
        any_order=False,
    )
    patch_assemble_master_key_providers.assert_called_once_with(sentinel.key_provider_1, sentinel.key_provider_2)
    assert test is sentinel.assembled_key_providers


def test_build_crypto_materials_manager_from_args_no_caching(
    patch_parse_master_key_providers, patch_aws_encryption_sdk
):
    test = master_key_parsing.build_crypto_materials_manager_from_args(
        key_providers_config=(sentinel.key_config_1, sentinel.key_config_2, sentinel.discovery), caching_config=None
    )

    patch_parse_master_key_providers.assert_called_once_with(
        sentinel.key_config_1, sentinel.key_config_2, sentinel.discovery
    )
    patch_aws_encryption_sdk.DefaultCryptoMaterialsManager.assert_called_once_with(
        patch_parse_master_key_providers.return_value
    )
    assert test is patch_aws_encryption_sdk.DefaultCryptoMaterialsManager.return_value


def test_build_crypto_materials_manager_from_args_with_caching(
    patch_parse_master_key_providers, patch_aws_encryption_sdk
):
    test = master_key_parsing.build_crypto_materials_manager_from_args(
        key_providers_config=(sentinel.key_config_1, sentinel.key_config_2),
        caching_config={"a": "cache_config_a", "b": "cache_config_b", "capacity": 5},
    )

    patch_aws_encryption_sdk.LocalCryptoMaterialsCache.assert_called_once_with(capacity=5)
    patch_aws_encryption_sdk.CachingCryptoMaterialsManager.assert_called_once_with(
        backing_materials_manager=patch_aws_encryption_sdk.DefaultCryptoMaterialsManager.return_value,
        cache=patch_aws_encryption_sdk.LocalCryptoMaterialsCache.return_value,
        a="cache_config_a",
        b="cache_config_b",
    )
    assert test is patch_aws_encryption_sdk.CachingCryptoMaterialsManager.return_value
