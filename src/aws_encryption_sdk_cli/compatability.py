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
"""Contains logic for checking ESDK and Python Version"""
import warnings


def _warn_end_of_support_cli():
    """Template for warning of end of support usage"""
    warning = (
        "This version of the aws-encryption-sdk-cli is no longer supported. "
        "To continue receiving new features, bug fixes, and security upates, "
        "please upgrade to the latest version. For more information, see SUPPORT_POLICY.rst: "
        "https://github.com/aws/aws-encryption-sdk-cli/blob/master/SUPPORT_POLICY.rst"
    )
    warnings.warn(warning, DeprecationWarning)
