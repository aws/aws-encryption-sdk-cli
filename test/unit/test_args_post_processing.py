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
"""Unit test suite for ``aws_encryption_sdk_cli.internal.args_post_processing``."""
from mock import sentinel
import pytest
from pytest_mock import mocker  # noqa pylint: disable=unused-import

from aws_encryption_sdk_cli.exceptions import BadUserArgumentError
from aws_encryption_sdk_cli.internal import args_post_processing


@pytest.yield_fixture
def patch_deepcopy(mocker):
    mocker.patch.object(args_post_processing.copy, 'deepcopy')
    yield args_post_processing.copy.deepcopy


@pytest.yield_fixture
def patch_botocore_session(mocker):
    mocker.patch.object(args_post_processing.botocore.session, 'Session')
    args_post_processing.botocore.session.Session.return_value = sentinel.botocore_session
    yield args_post_processing.botocore.session.Session


def test_nop_config(patch_deepcopy):
    test = args_post_processing.nop_config(sentinel.kwargs)

    patch_deepcopy.assert_called_once_with(sentinel.kwargs)
    assert test == patch_deepcopy.return_value


@pytest.mark.parametrize('source, result', (
    ({}, {}),  # empty baseline
    (  # arbitrary non-empty baseline
        {'a': 'a thing', 'b': 'another thing'},
        {'a': 'a thing', 'b': 'another thing'}
    ),
    (  # region_names without region
        {'a': 'a thing', 'region_names': ['us-east-2', 'ca-central-1']},
        {'a': 'a thing', 'region_names': ['us-east-2', 'ca-central-1']}
    ),
    (  # region without region_names
        {'a': 'a thing', 'region': ['eu-central-1']},
        {'a': 'a thing', 'region_names': ['eu-central-1']}
    ),
    (  # reigon and region_names specified
        {'a': 'a thing', 'region_names': ['us-east-2', 'ca-central-1'], 'region': ['eu-central-1']},
        {'a': 'a thing', 'region_names': ['eu-central-1']}
    ),
    (  # profile specified
        {'a': 'a thing', 'profile': [sentinel.profile_name]},
        {'a': 'a thing', 'botocore_session': sentinel.botocore_session}
    )
))
def test_kms_master_key_provider(patch_botocore_session, source, result):
    assert args_post_processing.kms_master_key_provider(source) == result


def test_kms_master_key_provider_botocore_session_call(patch_botocore_session):
    args_post_processing.kms_master_key_provider(dict(
        profile=['a profile name']
    ))

    patch_botocore_session.assert_called_once_with(profile='a profile name')


@pytest.mark.parametrize('profile_names', ([], [sentinel.a, sentinel.b]))
def test_kms_master_key_provider_not_one_profile(patch_botocore_session, profile_names):
    with pytest.raises(BadUserArgumentError) as excinfo:
        args_post_processing.kms_master_key_provider(dict(profile=profile_names))

    excinfo.match(r'Only one profile may be specified per master key provider configuration. *')
