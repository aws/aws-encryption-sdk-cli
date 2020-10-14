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
import logging
from collections import defaultdict

import aws_encryption_sdk
import pkg_resources
from aws_encryption_sdk import CachingCryptoMaterialsManager  # noqa pylint: disable=unused-import
from aws_encryption_sdk import DefaultCryptoMaterialsManager  # noqa pylint: disable=unused-import
from aws_encryption_sdk.key_providers.base import MasterKeyProvider  # noqa pylint: disable=unused-import

from aws_encryption_sdk_cli.exceptions import BadUserArgumentError
from aws_encryption_sdk_cli.internal.identifiers import MASTER_KEY_PROVIDERS_ENTRY_POINT, PLUGIN_NAMESPACE_DIVIDER
from aws_encryption_sdk_cli.internal.logging_utils import LOGGER_NAME

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Callable, DefaultDict, Dict, List, Union  # noqa pylint: disable=unused-import

    from aws_encryption_sdk_cli.internal.mypy_types import (  # noqa pylint: disable=unused-import
        CACHING_CONFIG,
        RAW_MASTER_KEY_PROVIDER_CONFIG,
    )
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

__all__ = ("build_crypto_materials_manager_from_args",)
_LOGGER = logging.getLogger(LOGGER_NAME)
_ENTRY_POINTS = defaultdict(dict)  # type: DefaultDict[str, Dict[str, pkg_resources.EntryPoint]]


def _discover_entry_points():
    # type: () -> None
    """Discover all registered entry points."""
    _LOGGER.debug("Discovering master key provider plugins")

    for entry_point in pkg_resources.iter_entry_points(MASTER_KEY_PROVIDERS_ENTRY_POINT):
        _LOGGER.info('Collecting plugin "%s" registered by "%s"', entry_point.name, entry_point.dist)
        _LOGGER.debug(
            "Plugin details: %s",
            dict(
                name=entry_point.name,
                module_name=entry_point.module_name,
                attrs=entry_point.attrs,
                extras=entry_point.extras,
                dist=entry_point.dist,
            ),
        )

        if PLUGIN_NAMESPACE_DIVIDER in entry_point.name:
            _LOGGER.warning(
                'Invalid substring "%s" in discovered entry point "%s". It will not be usable.',
                PLUGIN_NAMESPACE_DIVIDER,
                entry_point.name,
            )
            continue

        # mypy has trouble with pkgs_resources.iter_entry_points members
        _ENTRY_POINTS[entry_point.name][entry_point.dist.project_name] = entry_point  # type: ignore


def _entry_points():
    # type: () -> DefaultDict[str, Dict[str, pkg_resources.EntryPoint]]
    """Discover all entry points for required groups if they have not already been found.

    :returns: Mapping of group to name to entry points
    :rtype: dict
    """
    if not _ENTRY_POINTS:
        _discover_entry_points()
    return _ENTRY_POINTS


def _load_master_key_provider(name):
    # type: (str) -> Callable
    """Find the correct master key provider entry point for the specified name.

    :param str name: Name for which to look up entry point
    :returns: Loaded entry point
    :rtype: callable
    :raises BadUserArgumentError: if entry point cannot be found
    """
    if PLUGIN_NAMESPACE_DIVIDER in name:
        package_name, entry_point_name = name.split(PLUGIN_NAMESPACE_DIVIDER, 1)
    else:
        package_name = ""
        entry_point_name = name

    entry_points = _entry_points()[entry_point_name]

    if not entry_points:
        raise BadUserArgumentError('Requested master key provider not found: "{}"'.format(entry_point_name))

    if not package_name:
        if len(entry_points) == 1:
            return list(entry_points.values())[0].load()

        raise BadUserArgumentError(
            "Multiple entry points discovered and no package specified. Packages discovered registered by: ({})".format(
                ", ".join([str(entry.dist) for entry in entry_points.values()])
            )
        )

    try:
        return entry_points[package_name].load()
    except KeyError:
        raise BadUserArgumentError(
            (
                'Requested master key provider not found: "{requested}".'
                ' Packages discovered for "{entry_point}" registered by: ({discovered})'
            ).format(
                requested=name,
                entry_point=entry_point_name,
                discovered=", ".join([str(entry.dist) for entry in entry_points.values()]),
            )
        )


def _build_master_key_provider(provider, key, **kwargs):
    # type: (str, List[str], Union[str, List[str]]) -> MasterKeyProvider
    """Builds a master key provider using the supplied provider indicator and optional additional arguments.

    :param str provider: Provider indicator (may be known provider ID or classpath to class to use
    :param list key: List of key IDs with which to load master key provider
    :param **kwargs: Additional keyword arguments to pass to master key provider on instantiation
    :returns: Master key provider constructed as defined
    :rtype: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    """
    _LOGGER.debug("Loading provider: %s", provider)

    provider_callable = _load_master_key_provider(provider)
    key_provider = provider_callable(**kwargs)
    for single_key in key:
        key_provider.add_master_key(single_key)
    return key_provider


def _assemble_master_key_providers(primary_provider, *providers):
    # type: (MasterKeyProvider, List[MasterKeyProvider]) -> MasterKeyProvider
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
    :param bool discovery: Discovery mode
    :returns: MasterKeyProvider instance containing all referenced providers and keys
    :rtype: aws_encryption_sdk.key_providers.base.MasterKeyProvider
    """
    key_providers = []
    for provider_info in key_providers_info:
        info = copy.deepcopy(provider_info)
        provider = str(info.pop("provider"))
        key_ids = [str(key_id) for key_id in info.pop("key")]

        # Some implementations require a key_ids parameter as part of the kwargs, so explicitly set it here.
        info["key_ids"] = key_ids

        key_providers.append(_build_master_key_provider(provider=provider, key=key_ids, **info))

    return _assemble_master_key_providers(*key_providers)  # pylint: disable=no-value-for-parameter


def build_crypto_materials_manager_from_args(
    key_providers_config,  # type: List[RAW_MASTER_KEY_PROVIDER_CONFIG]
    caching_config,  # type: CACHING_CONFIG
):
    # type:(...) -> Union[CachingCryptoMaterialsManager, DefaultCryptoMaterialsManager]
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

    cache = aws_encryption_sdk.LocalCryptoMaterialsCache(capacity=caching_config.pop("capacity"))
    return aws_encryption_sdk.CachingCryptoMaterialsManager(
        backing_materials_manager=cmm, cache=cache, **caching_config
    )
