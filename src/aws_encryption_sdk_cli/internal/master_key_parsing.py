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
"""Helper functions for building crypto materials manager and underlying master key provider(s) from arguments."""
import copy
import importlib
import logging
from typing import Callable, List, Union  # noqa pylint: disable=unused-import

import aws_encryption_sdk
from aws_encryption_sdk.key_providers.base import MasterKeyProvider  # noqa pylint: disable=unused-import

from aws_encryption_sdk_cli.internal.args_post_processing import nop_post_processing
from aws_encryption_sdk_cli.internal.identifiers import KNOWN_MASTER_KEY_PROVIDERS
from aws_encryption_sdk_cli.internal.logging_utils import LOGGER_NAME
from aws_encryption_sdk_cli.internal.mypy_types import (  # noqa pylint: disable=unused-import
    CACHING_CONFIG, RAW_MASTER_KEY_PROVIDER_CONFIG
)

_LOGGER = logging.getLogger(LOGGER_NAME)


def _callable_loader(namespace_string):
    # type: (str) -> Callable
    """Load a callable object from a namespace string.

    :param str namespace_string: Full namespace path of desired callable
    :returns: callable object
    :raises ImportError: if unable to successfully import targetted callable
    """
    module_name, class_name = namespace_string.rsplit('.', 1)

    try:
        module = importlib.import_module(module_name)
    except TypeError:
        raise ImportError("No module named '{}'".format(module_name))

    try:
        loaded_callable = getattr(module, class_name)
        if not callable(loaded_callable):
            raise ImportError("Target callable '{target}' is not callable".format(target=namespace_string))
    except AttributeError:
        raise ImportError("Callable '{target}' not found in module '{module}'".format(
            target=class_name,
            module=module_name
        ))

    return loaded_callable


def _build_master_key_provider(provider, key, **kwargs):
    # type: (str, List[str], Union[str, List[str]]) -> MasterKeyProvider
    """Builds a master key provider using the supplied provider indicator and optional additional arguments.

    :param str provider: Provider indicator (may be known provider ID or classpath to class to use
    :param list key: List of key IDs with which to load master key provider
    :param **kwargs: Additional keyword arguments to pass to master key provider on instantiation
    :returns: Master key provider constructed as defined
    :rtype: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    """
    _LOGGER.debug('Loading provider: %s', provider)
    try:
        provider_config = KNOWN_MASTER_KEY_PROVIDERS[provider]
        provider_class_path = provider_config['callable']
        provider_post_processing_path = provider_config['post-processing']
        provider_post_processing = _callable_loader(provider_post_processing_path)
    except KeyError:
        provider_class_path = provider
        provider_post_processing = nop_post_processing

    provider_class = _callable_loader(provider_class_path)
    kwargs = provider_post_processing(kwargs)
    key_provider = provider_class(**kwargs)
    for single_key in key:
        key_provider.add_master_key(single_key)
    return key_provider


def _assemble_master_key_providers(primary_provider, *providers):
    # type: (MasterKeyProvider, MasterKeyProvider) -> MasterKeyProvider
    """Given one or more MasterKeyProvider instance, loads first MasterKeyProvider instance
    with all remaining MasterKeyProvider instances.

    :param primary_provider: MasterKeyProvider to use as the primary (ie: generates the Data Key)
    :type primary_provider: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    :param *providers: MasterKeyProviders to add to primary_provider
    :returns: primary_provider with all other providers added to it
    :rtype: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    """
    for provider in providers:
        primary_provider.add_master_key_provider(provider)
    return primary_provider


def _parse_master_key_providers_from_args(*key_providers_info):
    # type: (RAW_MASTER_KEY_PROVIDER_CONFIG) -> MasterKeyProvider
    """Parses the input key info from argparse and loads all key providers and key IDs.

    :param *key_providers_info: One or more dict containing key provider configuration (see _build_master_key_provider)
    :returns: MasterKeyProvider instance containing all referenced providers and keys
    :rtype: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    """
    key_providers = []
    for provider_info in key_providers_info:
        info = copy.deepcopy(provider_info)
        provider = str(info.pop('provider'))
        key_ids = [str(key_id) for key_id in info.pop('key')]
        key_providers.append(_build_master_key_provider(
            provider=provider,
            key=key_ids,
            **info
        ))

    return _assemble_master_key_providers(*key_providers)  # pylint: disable=no-value-for-parameter


def build_crypto_materials_manager_from_args(key_providers_config, caching_config):
    # type:(List[RAW_MASTER_KEY_PROVIDER_CONFIG], CACHING_CONFIG) -> aws_encryption_sdk.CachingCryptoMaterialsManager
    """Builds a cryptographic materials manager from the provided arguments.

    :param list key_providers_config: List of one or more dicts containing key provider configuration
    :param dict caching_config: Parsed caching configuration
    :rtype: aws_encryption_sdk.materials_managers.base.CryptoMaterialsManager
    """
    caching_config = copy.deepcopy(caching_config)
    key_provider = _parse_master_key_providers_from_args(*key_providers_config)
    cmm = aws_encryption_sdk.DefaultCryptoMaterialsManager(key_provider)

    if caching_config is None:
        return cmm

    cache = aws_encryption_sdk.LocalCryptoMaterialsCache(capacity=caching_config.pop('capacity'))
    return aws_encryption_sdk.CachingCryptoMaterialsManager(
        backing_materials_manager=cmm,
        cache=cache,
        **caching_config
    )
