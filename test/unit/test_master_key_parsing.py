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
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider
from mock import call, MagicMock, sentinel
import pytest
from pytest_mock import mocker  # noqa pylint: disable=unused-import

from aws_encryption_sdk_cli.exceptions import BadUserArgumentError
from aws_encryption_sdk_cli.internal import master_key_parsing
from aws_encryption_sdk_cli.internal.args_post_processing import (
    kms_master_key_provider_post_processing,
    nop_post_processing
)
from aws_encryption_sdk_cli.internal.identifiers import (
    MASTER_KEY_PROVIDER_ARGUMENT_PROCESSORS_ENTRY_POINT,
    MASTER_KEY_PROVIDERS_ENTRY_POINT
)


@pytest.yield_fixture
def patch_load_master_key_provider(mocker):
    mocker.patch.object(master_key_parsing, '_load_master_key_provider')
    yield master_key_parsing._load_master_key_provider


@pytest.yield_fixture
def patch_load_arguments_post_processor(mocker):
    mocker.patch.object(master_key_parsing, '_load_arguments_post_processor')
    yield master_key_parsing._load_arguments_post_processor


@pytest.yield_fixture
def patch_build_master_key_provider(mocker):
    mocker.patch.object(master_key_parsing, '_build_master_key_provider')
    master_key_parsing._build_master_key_provider.side_effect = (
        sentinel.key_provider_1,
        sentinel.key_provider_2
    )
    yield master_key_parsing._build_master_key_provider


@pytest.yield_fixture
def patch_assemble_master_key_providers(mocker):
    mocker.patch.object(master_key_parsing, '_assemble_master_key_providers')
    master_key_parsing._assemble_master_key_providers.return_value = sentinel.assembled_key_providers
    yield master_key_parsing._assemble_master_key_providers


@pytest.yield_fixture
def patch_parse_master_key_providers(mocker):
    mocker.patch.object(master_key_parsing, '_parse_master_key_providers_from_args')
    yield master_key_parsing._parse_master_key_providers_from_args


@pytest.yield_fixture
def patch_aws_encryption_sdk(mocker):
    mocker.patch.object(master_key_parsing, 'aws_encryption_sdk')
    yield master_key_parsing.aws_encryption_sdk


def test_entry_points():
    assert master_key_parsing._ENTRY_POINTS == master_key_parsing._load_entry_points()


def test_entry_points_aws_kms():
    assert master_key_parsing._ENTRY_POINTS[MASTER_KEY_PROVIDERS_ENTRY_POINT]['aws-kms'] == KMSMasterKeyProvider
    assert master_key_parsing._ENTRY_POINTS[
        MASTER_KEY_PROVIDER_ARGUMENT_PROCESSORS_ENTRY_POINT
    ]['aws-kms'] == kms_master_key_provider_post_processing


def test_load_master_key_provider_known():
    assert master_key_parsing._load_master_key_provider('aws-kms') == KMSMasterKeyProvider


def test_load_master_key_provider_unknown():
    with pytest.raises(BadUserArgumentError) as excinfo:
        master_key_parsing._load_master_key_provider(sentinel.unknown_name)

    excinfo.match(r'Unknown master key provider: *')


def test_load_arguments_post_processor_known():
    assert master_key_parsing._load_arguments_post_processor('aws-kms') == kms_master_key_provider_post_processing


def test_load_arguments_post_processor_unknown():
    assert master_key_parsing._load_arguments_post_processor(sentinel.unknown_name) == nop_post_processing


def test_build_master_key_provider_known_provider(patch_load_master_key_provider, patch_load_arguments_post_processor):
    mock_provider_callable = MagicMock()
    mock_post_processing = MagicMock(return_value={'c': sentinel.c})
    patch_load_master_key_provider.return_value = mock_provider_callable
    patch_load_arguments_post_processor.return_value = mock_post_processing
    test = master_key_parsing._build_master_key_provider(
        provider=sentinel.known_provider_id,
        key=[],
        a=sentinel.a,
        b=sentinel.b
    )
    patch_load_master_key_provider.assert_called_once_with(sentinel.known_provider_id)
    patch_load_arguments_post_processor.assert_called_once_with(sentinel.known_provider_id)
    mock_post_processing.assert_called_once_with({'a': sentinel.a, 'b': sentinel.b})
    mock_provider_callable.assert_called_once_with(c=sentinel.c)
    assert not mock_provider_callable.return_value.add_master_key.called
    assert test is mock_provider_callable.return_value


def test_build_master_key_provider_add_keys(patch_load_master_key_provider, patch_load_arguments_post_processor):
    mock_provider = MagicMock()
    patch_load_master_key_provider.return_value.return_value = mock_provider
    master_key_parsing._build_master_key_provider(
        provider=sentinel.unknown_provider_id,
        key=[
            sentinel.key_id_1,
            sentinel.key_id_2
        ]
    )
    mock_provider.add_master_key.assert_has_calls(
        calls=(
            call(sentinel.key_id_1),
            call(sentinel.key_id_2)
        ),
        any_order=False
    )


def test_build_master_key_provider_additional_kwargs(
        patch_load_master_key_provider,
        patch_load_arguments_post_processor
):
    kwargs = {'a': 1, 'b': 'asdf'}
    kwargs2 = {'c': 5, 'd': None}
    patch_load_arguments_post_processor.return_value.return_value = kwargs2
    master_key_parsing._build_master_key_provider(
        provider=sentinel.unknown_provider_id,
        key=[],
        **kwargs
    )
    patch_load_arguments_post_processor.return_value.assert_called_once_with(kwargs)
    patch_load_master_key_provider.return_value.assert_called_once_with(**kwargs2)


def test_assemble_master_key_providers():
    mock_primary = MagicMock()
    test = master_key_parsing._assemble_master_key_providers(
        mock_primary,
        sentinel.provider_1,
        sentinel.provider_2
    )
    mock_primary.add_master_key_provider.assert_has_calls(
        calls=(
            call(sentinel.provider_1),
            call(sentinel.provider_2)
        ),
        any_order=False
    )
    assert test is mock_primary


def test_parse_master_key_providers_from_args(patch_build_master_key_provider, patch_assemble_master_key_providers):
    test = master_key_parsing._parse_master_key_providers_from_args(
        {'provider': 'provider_1_a', 'key': ['provider_info_1_b']},
        {'provider': 'provider_2_a', 'key': ['provider_info_2_b'], 'z': 'additional_z'}
    )
    patch_build_master_key_provider.assert_has_calls(
        calls=(
            call(provider='provider_1_a', key=['provider_info_1_b']),
            call(provider='provider_2_a', key=['provider_info_2_b'], z='additional_z')
        ),
        any_order=False
    )
    patch_assemble_master_key_providers.assert_called_once_with(
        sentinel.key_provider_1,
        sentinel.key_provider_2
    )
    assert test is sentinel.assembled_key_providers


def test_build_crypto_materials_manager_from_args_no_caching(
        patch_parse_master_key_providers,
        patch_aws_encryption_sdk
):
    test = master_key_parsing.build_crypto_materials_manager_from_args(
        key_providers_config=(sentinel.key_config_1, sentinel.key_config_2),
        caching_config=None
    )

    patch_parse_master_key_providers.assert_called_once_with(sentinel.key_config_1, sentinel.key_config_2)
    patch_aws_encryption_sdk.DefaultCryptoMaterialsManager.assert_called_once_with(
        patch_parse_master_key_providers.return_value
    )
    assert test is patch_aws_encryption_sdk.DefaultCryptoMaterialsManager.return_value


def test_build_crypto_materials_manager_from_args_with_caching(
        patch_parse_master_key_providers,
        patch_aws_encryption_sdk
):
    test = master_key_parsing.build_crypto_materials_manager_from_args(
        key_providers_config=(sentinel.key_config_1, sentinel.key_config_2),
        caching_config={'a': 'cache_config_a', 'b': 'cache_config_b', 'capacity': 5}
    )

    patch_aws_encryption_sdk.LocalCryptoMaterialsCache.assert_called_once_with(capacity=5)
    patch_aws_encryption_sdk.CachingCryptoMaterialsManager.assert_called_once_with(
        backing_materials_manager=patch_aws_encryption_sdk.DefaultCryptoMaterialsManager.return_value,
        cache=patch_aws_encryption_sdk.LocalCryptoMaterialsCache.return_value,
        a='cache_config_a',
        b='cache_config_b'
    )
    assert test is patch_aws_encryption_sdk.CachingCryptoMaterialsManager.return_value
