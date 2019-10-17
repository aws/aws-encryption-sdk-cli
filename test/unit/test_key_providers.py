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
"""Unit test suite for ``aws_encryption_sdk_cli.key_providers``."""
import pytest
from mock import sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

from aws_encryption_sdk_cli import key_providers
from aws_encryption_sdk_cli.exceptions import BadUserArgumentError
from aws_encryption_sdk_cli.internal.identifiers import USER_AGENT_SUFFIX

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.yield_fixture
def patch_deepcopy(mocker):
    mocker.patch.object(key_providers.copy, "deepcopy")
    yield key_providers.copy.deepcopy


@pytest.yield_fixture
def patch_botocore_session(mocker):
    mocker.patch.object(key_providers.botocore.session, "Session")
    key_providers.botocore.session.Session.return_value = sentinel.botocore_session
    yield key_providers.botocore.session.Session


@pytest.yield_fixture
def patch_kms_master_key_provider(mocker):
    mocker.patch.object(key_providers, "KMSMasterKeyProvider")
    yield key_providers.KMSMasterKeyProvider


@pytest.mark.parametrize(
    "source, expected",
    (
        ({}, {"botocore_session": sentinel.botocore_session}),  # empty baseline
        (  # arbitrary non-empty baseline
            {"a": "a thing", "b": "another thing"},
            {"a": "a thing", "b": "another thing", "botocore_session": sentinel.botocore_session},
        ),
        (  # region_names without region
            {"a": "a thing", "region_names": ["us-east-2", "ca-central-1"]},
            {
                "a": "a thing",
                "region_names": ["us-east-2", "ca-central-1"],
                "botocore_session": sentinel.botocore_session,
            },
        ),
        (  # region without region_names
            {"a": "a thing", "region": ["eu-central-1"]},
            {"a": "a thing", "region_names": ["eu-central-1"], "botocore_session": sentinel.botocore_session},
        ),
        (  # region and region_names specified
            {"a": "a thing", "region_names": ["us-east-2", "ca-central-1"], "region": ["eu-central-1"]},
            {"a": "a thing", "region_names": ["eu-central-1"], "botocore_session": sentinel.botocore_session},
        ),
        (  # profile specified
            {"a": "a thing", "profile": [sentinel.profile_name]},
            {"a": "a thing", "botocore_session": sentinel.botocore_session},
        ),
    ),
)
def test_kms_master_key_provider_post_processing(
    patch_botocore_session, patch_kms_master_key_provider, source, expected
):
    test = key_providers.aws_kms_master_key_provider(**source)

    patch_kms_master_key_provider.assert_called_once_with(**expected)
    assert test is patch_kms_master_key_provider.return_value


def test_kms_master_key_provider_post_processing_named_profile(patch_botocore_session, patch_kms_master_key_provider):
    key_providers.aws_kms_master_key_provider(profile=["a profile name"])

    patch_botocore_session.assert_called_once_with(profile="a profile name")
    assert patch_botocore_session.return_value.user_agent_extra == USER_AGENT_SUFFIX


def test_kms_master_key_provider_post_processing_default_profile(patch_botocore_session, patch_kms_master_key_provider):
    key_providers.aws_kms_master_key_provider()

    patch_botocore_session.assert_called_once_with(profile=None)


@pytest.mark.parametrize("profile_names", ([], [sentinel.a, sentinel.b]))
def test_kms_master_key_provider_post_processing_not_one_profile(profile_names):
    with pytest.raises(BadUserArgumentError) as excinfo:
        key_providers.aws_kms_master_key_provider(profile=profile_names)

    excinfo.match(r"Only one profile may be specified per master key provider configuration. *")


@pytest.mark.parametrize("regions", ([], [sentinel.a, sentinel.b]))
def test_kms_master_key_provider_post_processing_not_one_region(regions):
    with pytest.raises(BadUserArgumentError) as excinfo:
        key_providers.aws_kms_master_key_provider(region=regions)

    excinfo.match(r"Only one region may be specified per master key provider configuration. *")
