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
"""Complex type constructions for use with mypy annotations."""
# mypy types confuse pylint: disable=invalid-name, unsubscriptable-object
try:  # Python 3.5.0 and 3.5.1 have incompatible typing modules
    import sys
    from typing import IO, Dict, List, Text, Union

    from aws_encryption_sdk import Algorithm
    from aws_encryption_sdk.materials_managers.base import CryptoMaterialsManager

    __all__ = (
        "STREAM_KWARGS",
        "CACHING_CONFIG",
        "RAW_MASTER_KEY_PROVIDER_CONFIG",
        "MASTER_KEY_PROVIDER_CONFIG",
        "RAW_CONFIG",
        "PARSED_CONFIG",
        "COLLAPSED_CONFIG",
        "SOURCE",
        "ARGPARSE_TEXT",
    )

    STREAM_KWARGS = Dict[str, Union[CryptoMaterialsManager, str, Dict[str, str], Algorithm, int]]
    CACHING_CONFIG = Dict[str, Union[str, int, float]]
    RAW_MASTER_KEY_PROVIDER_CONFIG = Dict[str, Union[str, List[str], Union[str, List[str]]]]
    MASTER_KEY_PROVIDER_CONFIG = Dict[str, Union[str, List[str]]]
    RAW_CONFIG = List[str]
    PARSED_CONFIG = Dict[str, List[str]]
    COLLAPSED_CONFIG = Dict[str, str]
    SOURCE = Union[Text, str, bytes, IO]

    # typeshed processing required to comply with argparse types
    if sys.version_info >= (3,):
        ARGPARSE_TEXT = str  # pylint: disable=invalid-name
    else:
        ARGPARSE_TEXT = Union[str, unicode]  # noqa:F821 pylint: disable=undefined-variable
except ImportError:  # pragma: no cover
    # We only actually need these when running the mypy checks
    pass
