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
from mock import call, MagicMock, sentinel
import pytest
from pytest_mock import mocker  # noqa pylint: disable=unused-import

from aws_encryption_sdk_cli.internal import master_key_parsing


@pytest.yield_fixture
def patch_importlib(mocker):
    mocker.patch.object(master_key_parsing.importlib, 'import_module')
    yield master_key_parsing.importlib.import_module


@pytest.yield_fixture
def patch_callable_loader(mocker):
    mocker.patch.object(master_key_parsing, '_callable_loader')
    yield master_key_parsing._callable_loader


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


def test_callable_loader_fail_no_module(patch_importlib):
    patch_importlib.side_effect = TypeError

    with pytest.raises(ImportError) as excinfo:
        master_key_parsing._callable_loader('module.namespace.classname')

    excinfo.match(r"No module named 'module.namespace'")


def test_callable_loader_fail_callable_not_found(patch_importlib):
    patch_importlib.return_value = AttributeError

    with pytest.raises(ImportError) as excinfo:
        master_key_parsing._callable_loader('module.namespace.classname')

    excinfo.match(r"Callable 'classname' not found in module 'module.namespace'")


def test_callable_loader_fail_callable_not_callable(patch_importlib):
    patch_importlib.return_value = MagicMock(classname=None)

    with pytest.raises(ImportError) as excinfo:
        master_key_parsing._callable_loader('module.namespace.classname')

    excinfo.match(r"Target callable 'module.namespace.classname' is not callable")


def test_callable_loader_return(patch_importlib):
    test = master_key_parsing._callable_loader('module.namespace.classname')
    patch_importlib.assert_called_once_with('module.namespace')
    assert test is patch_importlib.return_value.classname


def test_callable_loader_json_decoder_success():
    master_key_parsing._callable_loader('json.JSONDecoder')


def test_build_master_key_provider_known_provider(mocker, patch_callable_loader):
    mocker.patch.object(master_key_parsing, 'KNOWN_MASTER_KEY_PROVIDERS')
    master_key_parsing.KNOWN_MASTER_KEY_PROVIDERS = {sentinel.known_provider_id: sentinel.known_provider_classpath}
    test = master_key_parsing._build_master_key_provider(
        provider=sentinel.known_provider_id,
        key=[]
    )
    patch_callable_loader.assert_called_once_with(sentinel.known_provider_classpath)
    patch_callable_loader.return_value.assert_called_once_with()
    assert not patch_callable_loader.return_value.return_value.add_master_key.called
    assert test is patch_callable_loader.return_value.return_value


def test_build_master_key_provider_unknown_key_provider(patch_callable_loader):
    test = master_key_parsing._build_master_key_provider(
        provider=sentinel.unknown_provider_id,
        key=[]
    )
    patch_callable_loader.assert_called_once_with(sentinel.unknown_provider_id)
    patch_callable_loader.return_value.assert_called_once_with()
    assert test is patch_callable_loader.return_value.return_value


def test_build_master_key_provider_add_keys(patch_callable_loader):
    mock_provider = MagicMock()
    patch_callable_loader.return_value.return_value = mock_provider
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


def test_build_master_key_provider_additional_kwargs(patch_callable_loader):
    kwargs = {'a': 1, 'b': 'asdf'}
    master_key_parsing._build_master_key_provider(
        provider=sentinel.unknown_provider_id,
        key=[],
        **kwargs
    )
    patch_callable_loader.return_value.assert_called_once_with(**kwargs)


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
        {'a': sentinel.provider_info_1_a, 'b': sentinel.provider_info_1_b},
        {'a': sentinel.provider_info_2_a, 'b': sentinel.provider_info_2_b}
    )
    patch_build_master_key_provider.assert_has_calls(
        calls=(
            call(a=sentinel.provider_info_1_a, b=sentinel.provider_info_1_b),
            call(a=sentinel.provider_info_2_a, b=sentinel.provider_info_2_b)
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
        materials_manager=patch_aws_encryption_sdk.DefaultCryptoMaterialsManager.return_value,
        cache=patch_aws_encryption_sdk.LocalCryptoMaterialsCache.return_value,
        a='cache_config_a',
        b='cache_config_b'
    )
    assert test is patch_aws_encryption_sdk.CachingCryptoMaterialsManager.return_value
