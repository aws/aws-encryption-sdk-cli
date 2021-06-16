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
"""Master key providers."""
import copy

import botocore.session
from aws_encryption_sdk.key_providers.kms import (
    DiscoveryFilter,
    MRKAwareDiscoveryAwsKmsMasterKeyProvider,
    MRKAwareStrictAwsKmsMasterKeyProvider,
)

from aws_encryption_sdk_cli.exceptions import BadUserArgumentError
from aws_encryption_sdk_cli.internal.identifiers import USER_AGENT_SUFFIX

try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    from typing import Dict, List, Optional, Text, Union  # noqa pylint: disable=unused-import
except ImportError:  # pragma: no cover
    # We only actually need these imports when running the mypy checks
    pass

__all__ = ("aws_kms_master_key_provider",)


def aws_kms_master_key_provider(
    discovery=True,  # type: bool
    **kwargs  # type: List[Union[Text, str]]
):
    # type: (...) -> Union[MRKAwareDiscoveryAwsKmsMasterKeyProvider, MRKAwareStrictAwsKmsMasterKeyProvider]
    """Apply post-processing to transform ``KMSMasterKeyProvider``-specific values from CLI
    arguments to valid ``KMSMasterKeyProvider`` parameters, then call ``KMSMasterKeyProvider``
    with those parameters.

    :param bool discovery: Return a MRKAwareDiscoveryAwsKmsMasterKeyProvider
    :param dict kwargs: Named parameters collected from CLI arguments as prepared
        in aws_encryption_sdk_cli.internal.master_key_parsing._parse_master_key_providers_from_args
    :rtype: aws_encryption_sdk.key_providers.kms.BaseKMSMasterKeyProvider
    """
    kwargs = copy.deepcopy(kwargs)
    try:
        profile_names = kwargs.pop("profile")
        if len(profile_names) != 1:
            raise BadUserArgumentError(
                "Only one profile may be specified per master key provider configuration. {} provided.".format(
                    len(profile_names)
                )
            )
        profile_name = profile_names[0]  # type: Optional[Text]
    except KeyError:
        profile_name = None

    botocore_session = botocore.session.Session(profile=profile_name)
    botocore_session.user_agent_extra = USER_AGENT_SUFFIX
    kwargs["botocore_session"] = botocore_session

    try:
        region_name = kwargs.pop("region")
        if len(region_name) != 1:
            raise BadUserArgumentError(
                "Only one region may be specified per master key provider configuration. {} provided.".format(
                    len(region_name)
                )
            )
        kwargs["region_names"] = region_name
    except KeyError:
        pass
    if discovery:
        accounts = kwargs.pop("discovery-account", None)
        partition = kwargs.pop("discovery-partition", None)
        if accounts and partition:
            discovery_filter = DiscoveryFilter(account_ids=accounts, partition=partition)
            kwargs["discovery_filter"] = discovery_filter  # type: ignore

        return MRKAwareDiscoveryAwsKmsMasterKeyProvider(**kwargs)
    return MRKAwareStrictAwsKmsMasterKeyProvider(**kwargs)
