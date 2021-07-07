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
"""Unit testing suite for ``aws_encryption_sdk_cli.internal.arg_parsing``."""
import os
import platform
import re
import shlex

import aws_encryption_sdk
import pytest
from aws_encryption_sdk.materials_managers import CommitmentPolicy
from mock import MagicMock, sentinel
from pytest_mock import mocker  # noqa pylint: disable=unused-import

import aws_encryption_sdk_cli
from aws_encryption_sdk_cli.exceptions import ParameterParseError
from aws_encryption_sdk_cli.internal import arg_parsing, identifiers, metadata

pytestmark = [pytest.mark.unit, pytest.mark.local]


@pytest.fixture
def patch_platform_win32_ver(mocker):
    mocker.patch.object(arg_parsing.platform, "win32_ver")
    return arg_parsing.platform.win32_ver


@pytest.fixture
def patch_build_parser(mocker):
    mocker.patch.object(arg_parsing, "_build_parser")
    yield arg_parsing._build_parser


@pytest.fixture
def patch_process_wrapping_key_provider_configs(mocker):
    mocker.patch.object(arg_parsing, "_process_wrapping_key_provider_configs")
    yield arg_parsing._process_wrapping_key_provider_configs


@pytest.fixture
def patch_parse_and_collapse_config(mocker):
    mocker.patch.object(arg_parsing, "_parse_and_collapse_config")
    yield arg_parsing._parse_and_collapse_config


@pytest.fixture
def patch_process_encryption_context(mocker):
    mocker.patch.object(arg_parsing, "_process_encryption_context")
    arg_parsing._process_encryption_context.return_value = sentinel.encryption_context, sentinel.required_keys
    yield arg_parsing._process_encryption_context


@pytest.fixture
def patch_process_caching_config(mocker):
    mocker.patch.object(arg_parsing, "_process_caching_config")
    yield arg_parsing._process_caching_config


def test_version_report():
    test = arg_parsing._version_report()
    assert test == "aws-encryption-sdk-cli/{cli} aws-encryption-sdk/{sdk}".format(
        cli=aws_encryption_sdk_cli.__version__, sdk=aws_encryption_sdk.__version__
    )


@pytest.mark.parametrize(
    "arg_line, line_args",
    (
        (  # The default converter leaves a space in front of the first argument
            # when called like this. Make sure we do not.
            "-f test1 test2",
            ["-f", "test1", "test2"],
        ),
        ("   test1   test2    ", ["test1", "test2"]),
        ("-f test1 test2 # in-line comment", ["-f", "test1", "test2"]),
        ("# whole-line comment", []),
        (
            "-f " + os.path.join("~", "my", "special", "file"),
            ["-f", os.path.join(os.path.expanduser("~"), "my", "special", "file")],
        ),
        ("-f $ANOTHER_VAR ${MY_SPECIAL_VAR}PlusSome", ["-f", "someOtherData", "aVerySpecialPrefixPlusSome"]),
    ),
)
def test_comment_ignoring_argument_parser_convert_arg_line_to_args(monkeypatch, arg_line, line_args):
    monkeypatch.setenv("MY_SPECIAL_VAR", "aVerySpecialPrefix")
    monkeypatch.setenv("ANOTHER_VAR", "someOtherData")
    parser = arg_parsing.CommentIgnoringArgumentParser()
    parsed_line = list(parser.convert_arg_line_to_args(arg_line))
    assert line_args == parsed_line


POSIX_FILEPATH = ("-i test/file/path", ["-i", "test/file/path"])
NON_POSIX_FILEPATH = ("-i test\\file\\path", ["-i", "test\\file\\path"])


@pytest.mark.parametrize(
    "win32_version, expected_transform",
    ((("", "", ""), POSIX_FILEPATH), (("10", "10.0.0", "SP0", "Multiprocessor Free"), NON_POSIX_FILEPATH)),
)
def test_comment_ignoring_argument_parser_convert_filename(patch_platform_win32_ver, win32_version, expected_transform):
    patch_platform_win32_ver.return_value = win32_version
    parser = arg_parsing.CommentIgnoringArgumentParser()

    if any(win32_version):
        assert parser._CommentIgnoringArgumentParser__is_windows
    else:
        assert not parser._CommentIgnoringArgumentParser__is_windows

    parsed_line = list(parser.convert_arg_line_to_args(expected_transform[0]))
    assert expected_transform[1] == parsed_line


def build_convert_special_cases():
    test_cases = []
    escape_chars = {False: "\\", True: "`"}
    for plat_is_windows in (True, False):
        test_cases.append(
            (
                '-o "example file with spaces surrounded by double quotes"',
                ["-o", "example file with spaces surrounded by double quotes"],
                plat_is_windows,
            )
        )
        test_cases.append(
            (
                "-o 'example file with spaces surrounded by single quotes'",
                ["-o", "example file with spaces surrounded by single quotes"],
                plat_is_windows,
            )
        )
        test_cases.append(
            (
                '-o "example with an inner {}" double quote"'.format(escape_chars[plat_is_windows]),
                ["-o", 'example with an inner " double quote'],
                plat_is_windows,
            )
        )
        test_cases.append(
            (
                "-o 'example with an inner {}' single quote'".format(escape_chars[plat_is_windows]),
                ["-o", "example with an inner ' single quote"],
                plat_is_windows,
            )
        )
    return test_cases


@pytest.mark.parametrize("arg_line, expected_args, plat_is_windows", build_convert_special_cases())
def test_comment_ignoring_argument_parser_convert_special_cases(arg_line, expected_args, plat_is_windows):
    parser = arg_parsing.CommentIgnoringArgumentParser()
    parser._CommentIgnoringArgumentParser__is_windows = plat_is_windows

    actual_args = parser.convert_arg_line_to_args(arg_line)

    assert actual_args == expected_args


@pytest.mark.functional
def test_f_comment_ignoring_argument_parser_convert_filename():
    # Actually checks against the current local system
    parser = arg_parsing.CommentIgnoringArgumentParser()

    if any(platform.win32_ver()):
        assert parser._CommentIgnoringArgumentParser__is_windows
        expected_transform = NON_POSIX_FILEPATH
    else:
        assert not parser._CommentIgnoringArgumentParser__is_windows
        expected_transform = POSIX_FILEPATH

    parsed_line = list(parser.convert_arg_line_to_args(expected_transform[0]))
    assert expected_transform[1] == parsed_line


def test_unique_store_action_first_call():
    mock_parser = MagicMock()
    mock_namespace = MagicMock(special_attribute=None)
    action = arg_parsing.UniqueStoreAction(option_strings=sentinel.option_strings, dest="special_attribute")
    action(parser=mock_parser, namespace=mock_namespace, values=sentinel.values, option_string="SPECIAL_ATTRIBUTE")
    assert mock_namespace.special_attribute is sentinel.values


def test_unique_store_action_second_call():
    mock_parser = MagicMock()
    mock_namespace = MagicMock(special_attribute=sentinel.attribute)
    action = arg_parsing.UniqueStoreAction(option_strings=sentinel.option_strings, dest="special_attribute")
    action(parser=mock_parser, namespace=mock_namespace, values=sentinel.values, option_string="SPECIAL_ATTRIBUTE")
    assert mock_namespace.special_attribute is sentinel.attribute
    mock_parser.error.assert_called_once_with("SPECIAL_ATTRIBUTE argument may not be specified more than once")


def build_expected_good_args(from_file=False):  # pylint: disable=too-many-locals,too-many-statements
    encrypt = "-e"
    decrypt = "-d"
    suppress_metadata = " -S"
    short_input = " -i -"
    long_input = " --input -"
    short_output = " -o -"
    long_output = " --output -"
    valid_io = short_input + short_output
    mkp_1 = " -w provider=ex_provider_1 key=ex_mk_id_1"
    mkp_1_parsed = {"provider": "ex_provider_1", "key": ["ex_mk_id_1"]}
    mkp_2 = " -w provider=ex_provider_2 key=ex_mk_id_2"
    mkp_2_parsed = {"provider": "ex_provider_2", "key": ["ex_mk_id_2"]}
    default_encrypt = encrypt + suppress_metadata + valid_io + mkp_1
    good_args = []

    # encrypt/decrypt
    for encrypt_flag in (encrypt, "--encrypt"):
        good_args.append((encrypt_flag + suppress_metadata + valid_io + mkp_1, "action", "encrypt"))
    for decrypt_flag in (decrypt, "--decrypt"):
        good_args.append((decrypt_flag + suppress_metadata + valid_io + mkp_1, "action", "decrypt"))
    good_args.append(("--decrypt-unsigned" + suppress_metadata + valid_io + mkp_1, "action", "decrypt-unsigned"))

    # wrapping key config
    good_args.append((default_encrypt, "wrapping_keys", [mkp_1_parsed]))
    good_args.append((default_encrypt + mkp_2, "wrapping_keys", [mkp_1_parsed, mkp_2_parsed]))

    # input/output
    for input_flag in (short_input, long_input):
        good_args.append((encrypt + suppress_metadata + input_flag + short_output + mkp_1, "input", "-"))
    for output_flag in (short_output, long_output):
        good_args.append((encrypt + suppress_metadata + output_flag + short_input + mkp_1, "output", "-"))

    # encryption context
    good_args.append((default_encrypt, "encryption_context", {}))
    good_args.append(
        (default_encrypt + " -c some=data not=secret", "encryption_context", {"some": "data", "not": "secret"})
    )
    if from_file:
        good_args.append(
            (
                default_encrypt + ' -c "key with a space=value with a space"',
                "encryption_context",
                {"key with a space": "value with a space"},
            )
        )
    else:
        good_args.append(
            (
                default_encrypt + ' -c "key with a space=value with a space"',
                "encryption_context",
                {"key with a space": "value with a space"},
            )
        )

    # algorithm
    algorithm_name = "AES_128_GCM_IV12_TAG16"
    good_args.append((default_encrypt, "algorithm", None))
    good_args.append((default_encrypt + " --algorithm " + algorithm_name, "algorithm", algorithm_name))

    # frame length
    good_args.append((default_encrypt, "frame_length", None))
    good_args.append((default_encrypt + " --frame-length 99", "frame_length", 99))

    # max length
    good_args.append((default_encrypt, "max_length", None))
    good_args.append((default_encrypt + " --max-length 99", "max_length", 99))

    # max encrypted data keys
    good_args.append((default_encrypt, "max_encrypted_data_keys", None))
    good_args.append((default_encrypt + " --max-encrypted-data-keys 99", "max_encrypted_data_keys", 99))

    # interactive
    good_args.append((default_encrypt, "interactive", False))
    good_args.append((default_encrypt + " --interactive", "interactive", True))

    # no-overwrite
    good_args.append((default_encrypt, "no_overwrite", False))
    good_args.append((default_encrypt + " --no-overwrite", "no_overwrite", True))

    # suffix
    good_args.append((default_encrypt + " --suffix .MY_SPECIAL_SUFFIX", "suffix", ".MY_SPECIAL_SUFFIX"))
    good_args.append((default_encrypt + " --suffix", "suffix", ""))

    # recursive
    good_args.append((default_encrypt, "recursive", False))
    for recursive_flag in (" -r", " -R", " --recursive"):
        good_args.append((default_encrypt + recursive_flag, "recursive", True))

    # logging verbosity
    good_args.append((default_encrypt, "verbosity", None))
    for count in (1, 2, 3, 4):
        good_args.append((default_encrypt + " -" + "v" * count, "verbosity", count))

    # metadata output
    good_args.append((default_encrypt, "metadata_output", metadata.MetadataWriter(suppress_output=True)()))
    good_args.append(
        (
            encrypt + valid_io + mkp_1 + " --metadata-output -",
            "metadata_output",
            metadata.MetadataWriter(suppress_output=False)(output_file="-"),
        )
    )

    # buffer
    good_args.append((default_encrypt, "buffer", False))
    for recursive_flag in (" -b", " --buffer"):
        good_args.append((default_encrypt + recursive_flag, "buffer", True))

    return good_args


@pytest.mark.parametrize("argstring, attribute, value", build_expected_good_args())
def test_parser_from_shell(argstring, attribute, value):
    parsed = arg_parsing.parse_args(shlex.split(argstring))
    assert getattr(parsed, attribute) == value


@pytest.mark.parametrize("argstring, attribute, value", build_expected_good_args(from_file=True))
def test_parser_fromfile(tmpdir, argstring, attribute, value):
    argfile = tmpdir.join("argfile")
    argfile.write(argstring)
    parsed = arg_parsing.parse_args(["@{}".format(argfile)])
    assert getattr(parsed, attribute) == value


def build_bad_io_arguments():
    return [
        "-d -S -o - -w provider=ex_provider key=ex_mk_id",
        "-d -S -i - -w provider=ex_provider key=ex_mk_id",
        "-d -S -i - -o - --required-encryption-context-keys asd asdfa",
    ]


def build_bad_multiple_arguments():
    prefix = "-d -S -i - -o -"
    protected_arguments = [
        " --caching key=value",
        " --input -",
        " --output -",
        " --encryption-context key=value",
        " --algorithm ALGORITHM",
        " --frame-length 256",
        " --max-length 1024",
        " --suffix .MY_SPECIAL_SUFFIX",
    ]
    return [prefix + arg + arg for arg in protected_arguments]


def build_bad_dummy_arguments():
    parser = arg_parsing._build_parser()
    dummy_arguments = parser._CommentIgnoringArgumentParser__dummy_arguments
    bad_commands = []
    safe_pattern = "-d -S -i - -o - {arg}"
    partial_patterns = {
        "-decrypt": "{arg} -i - -o - -S",
        "-encrypt": "{arg} -i - -o - -S",
        "-decrypt-unsigned": "{arg} -i - -o - -S",
        "-input": "-d {arg} - -o - -S",
        "-output": "-d -i - {arg} - -S",
    }
    for arg in dummy_arguments:
        pattern = partial_patterns.get(arg, safe_pattern)
        bad_commands.append(pattern.format(arg=arg))
    return bad_commands


def test_dummy_arguments_covered():
    parser = arg_parsing._build_parser()
    expected_dummy_commands = []
    for action in parser._actions:
        for opt in action.option_strings:
            if opt.startswith(parser.prefix_chars * 2):
                expected_dummy_commands.append(opt[1:])

    assert set(expected_dummy_commands) == set(parser._CommentIgnoringArgumentParser__dummy_arguments)


@pytest.mark.parametrize(
    "args", build_bad_io_arguments() + build_bad_multiple_arguments() + build_bad_dummy_arguments()
)
def test_parse_args_fail(args):
    with pytest.raises(SystemExit) as excinfo:
        arg_parsing.parse_args(shlex.split(args))

    assert excinfo.value.args == (2,)


def test_parse_args_wrapping_keys_required():
    args = "-d -S -o - -i -"

    with pytest.raises(SystemExit) as excinfo:
        arg_parsing.parse_args(shlex.split(args))

    assert excinfo.value.args == (2,)


@pytest.mark.parametrize(
    "source, expected",
    (
        (["a=b", "c=d", "e=f"], {"a": ["b"], "c": ["d"], "e": ["f"]}),
        (["a=b", "b=c", "b=d"], {"a": ["b"], "b": ["c", "d"]}),
    ),
)
def test_parse_kwargs_good(source, expected):
    test = arg_parsing._parse_kwargs(source)

    assert test == expected


@pytest.mark.parametrize("bad_arg", ("key_without_value", "key_with_empty_value=", "=value_with_empty_key"))
def test_parse_kwargs_fail(bad_arg):
    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing._parse_kwargs([bad_arg])

    excinfo.match(r'Argument parameter must follow the format "key=value"')


def test_collapse_config():
    source = {"a": ["b"], "c": ["d"], "e": ["f"]}
    expected = {"a": "b", "c": "d", "e": "f"}

    test = arg_parsing._collapse_config(source)

    assert test == expected


def test_parse_and_collapse_config():
    source = ["key1=value1", "key2=value2", "key3=value3"]
    expected = {"key1": "value1", "key2": "value2", "key3": "value3"}

    test = arg_parsing._parse_and_collapse_config(source)

    assert test == expected


def test_process_caching_config():
    source = ["capacity=3", "max_messages_encrypted=55", "max_bytes_encrypted=8", "max_age=32"]
    expected = {"capacity": 3, "max_messages_encrypted": 55, "max_bytes_encrypted": 8, "max_age": 32.0}

    test = arg_parsing._process_caching_config(source)

    assert test == expected


def test_process_caching_config_bad_key():
    source = ["capacity=3", "max_age=32", "asdifhja9woiefhjuaowiefjoawiuehjc9awehf=fjw28304uq20498gfij83w0erifju"]

    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing._process_caching_config(source)

    excinfo.match(r'Invalid caching configuration key: "asdifhja9woiefhjuaowiefjoawiuehjc9awehf"')


@pytest.mark.parametrize(
    "source",
    (
        ["max_messages_encrypted=55", "max_bytes_encrypted=8", "max_age=32"],  # no caopacity
        ["capacity=3", "max_messages_encrypted=55", "max_bytes_encrypted=8"],  # no max_age
    ),
)
def test_process_caching_config_required_parameters_missing(source):
    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing._process_caching_config(source)

    excinfo.match(r'If enabling caching, both "capacity" and "max_age" are required')


KEY_PROVIDER_CONFIGS = [
    (  # single key, encrypt
        [["provider=ex_provider", "key=ex_key"]],
        "encrypt",
        [{"provider": "ex_provider", "key": ["ex_key"]}],
    ),
    (  # multiple keys
        [["provider=ex_provider", "key=ex_key_1", "key=ex_key_2"]],
        "encrypt",
        [{"provider": "ex_provider", "key": ["ex_key_1", "ex_key_2"]}],
    ),
    (  # unknown parameters
        [["provider=ex_provider", "key=ex_key_1", "key=ex_key_2", "a=b", "asdf=4"]],
        "encrypt",
        [{"provider": "ex_provider", "key": ["ex_key_1", "ex_key_2"], "a": ["b"], "asdf": ["4"]}],
    ),
    (  # decrypt, with keys, no discovery
        [["provider=ex_provider", "key=ex_key_1"]],
        "decrypt",
        [{"provider": "ex_provider", "key": ["ex_key_1"]}],
    ),
    (  # decrypt, aws-kms, with keys, no discovery
        [["provider=aws-kms", "key=ex_key"]],
        "decrypt",
        [{"provider": "aws-kms", "key": ["ex_key"], "discovery": False}],
    ),
    (  # decrypt, explicit discovery true, no filter
        [["provider=aws-kms", "discovery=true"]],
        "decrypt",
        [{"provider": "aws-kms", "key": [], "discovery": True}],
    ),
    (  # decrypt, explicit discovery false, no filter
        [["provider=aws-kms", "discovery=false", "key=ex_key_1"]],
        "decrypt",
        [{"provider": "aws-kms", "key": ["ex_key_1"], "discovery": False}],
    ),
    (  # decrypt, explicit discovery, filter
        [["provider=aws-kms", "discovery=true", "discovery-account=123", "discovery-partition=aws"]],
        "decrypt",
        [
            {
                "provider": "aws-kms",
                "key": [],
                "discovery": True,
                "discovery-account": ["123"],
                "discovery-partition": "aws",
            }
        ],
    ),
    (  # decrypt, explicit discovery, filter multiple accounts
        [
            [
                "provider=aws-kms",
                "discovery=true",
                "discovery-account=123",
                "discovery-account=456",
                "discovery-partition=aws",
            ]
        ],
        "decrypt",
        [
            {
                "provider": "aws-kms",
                "key": [],
                "discovery": True,
                "discovery-account": ["123", "456"],
                "discovery-partition": "aws",
            }
        ],
    ),
    (  # decrypt-unsigned, with keys, no discovery
        [["provider=ex_provider", "key=ex_key_1"]],
        "decrypt-unsigned",
        [{"provider": "ex_provider", "key": ["ex_key_1"]}],
    ),
    (  # decrypt-unsigned, explicit discovery true, no filter
        [["provider=aws-kms", "discovery=true"]],
        "decrypt-unsigned",
        [{"provider": "aws-kms", "key": [], "discovery": True}],
    ),
    (  # decrypt-unsigned, explicit discovery false, no filter
        [["provider=aws-kms", "discovery=false", "key=ex_key_1"]],
        "decrypt-unsigned",
        [{"provider": "aws-kms", "key": ["ex_key_1"], "discovery": False}],
    ),
    (  # decrypt-unsigned, explicit discovery, filter
        [["provider=aws-kms", "discovery=true", "discovery-account=123", "discovery-partition=aws"]],
        "decrypt-unsigned",
        [
            {
                "provider": "aws-kms",
                "key": [],
                "discovery": True,
                "discovery-account": ["123"],
                "discovery-partition": "aws",
            }
        ],
    ),
    (  # decrypt-unsigned, explicit discovery, filter multiple accounts
        [
            [
                "provider=aws-kms",
                "discovery=true",
                "discovery-account=123",
                "discovery-account=456",
                "discovery-partition=aws",
            ]
        ],
        "decrypt-unsigned",
        [
            {
                "provider": "aws-kms",
                "key": [],
                "discovery": True,
                "discovery-account": ["123", "456"],
                "discovery-partition": "aws",
            }
        ],
    ),
    (  # decrypt, non-kms provider, explicit discovery true
        [["provider=" + identifiers.DEFAULT_MASTER_KEY_PROVIDER, "discovery=true"]],
        "decrypt",
        [{"provider": identifiers.DEFAULT_MASTER_KEY_PROVIDER, "key": [], "discovery": True}],
    ),
    (  # decrypt-unsigned, non-kms provider, explicit discovery true
        [["provider=" + identifiers.DEFAULT_MASTER_KEY_PROVIDER, "discovery=true"]],
        "decrypt-unsigned",
        [{"provider": identifiers.DEFAULT_MASTER_KEY_PROVIDER, "key": [], "discovery": True}],
    ),
    (
        [["key=ex_key_1"]],
        "encrypt",
        [{"provider": identifiers.DEFAULT_MASTER_KEY_PROVIDER, "key": ["ex_key_1"], "discovery": False}],
    ),
]


@pytest.mark.parametrize("source, action, expected", KEY_PROVIDER_CONFIGS)
def test_process_wrapping_key_provider_configs(source, action, expected):
    test = arg_parsing._process_wrapping_key_provider_configs(source, action)

    assert test == expected


def test_process_wrapping_key_provider_configs_no_provider_on_encrypt():
    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing._process_wrapping_key_provider_configs(None, "encrypt")

    excinfo.match(r"No wrapping key provider configuration found")


def test_process_wrapping_key_provider_configs_encrypt_with_discovery():
    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing._process_wrapping_key_provider_configs([["discovery=true"]], "encrypt")

    excinfo.match(r"Discovery attributes are supported only on decryption for AWS KMS keys")


@pytest.mark.parametrize("decrypt_mode", ("decrypt", "decrypt-unsigned"))
def test_process_wrapping_key_provider_configs_decrypt_without_discovery(decrypt_mode):
    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing._process_wrapping_key_provider_configs([["provider=aws-kms"]], decrypt_mode)

    excinfo.match(re.escape("When discovery is false (disabled), you must specify at least one wrapping key"))


@pytest.mark.parametrize("decrypt_mode", ("decrypt", "decrypt-unsigned"))
def test_process_wrapping_key_provider_configs_multiple_discovery_partition(decrypt_mode):
    args = [["discovery=true", "discovery-account=123", "discovery-partition=aws", "discovery-partition=aws-gov"]]
    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing._process_wrapping_key_provider_configs(args, decrypt_mode)

    excinfo.match(r"You can only specify discovery-partition once")


def test_process_wrapping_key_provider_configs_not_exactly_one_provider():
    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing._process_wrapping_key_provider_configs(
            [["provider=a", "provider=b", "key=ex_key_1", "key=ex_key_2"]], "encrypt"
        )

    excinfo.match(r'You must provide exactly one "provider" for each wrapping key provider configuration. 2 provided')


@pytest.mark.parametrize("decrypt_mode", ("decrypt", "decrypt-unsigned"))
@pytest.mark.parametrize("args", ["discovery=true", "discovery-account=123", "discovery-partition=aws"])
def test_process_wrapping_key_provider_configs_discovery_with_nonkms_provider(args, decrypt_mode):
    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing._process_wrapping_key_provider_configs([["provider=notkms", args]], decrypt_mode)

    excinfo.match(r"Discovery attributes are supported only for AWS KMS wrapping keys")


def test_process_wrapping_key_provider_configs_no_keys():
    source = [["provider=ex_provider", "aaa=sadfa"]]

    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing._process_wrapping_key_provider_configs(source, "encrypt")

    excinfo.match(r'At least one "key" must be provided for each wrapping key provider configuration')


def test_parse_args(
    patch_build_parser,
    patch_process_wrapping_key_provider_configs,
    patch_process_encryption_context,
    patch_process_caching_config,
):
    mock_discovery_account = [[123]]
    mock_parsed_args = MagicMock(
        wrapping_keys=sentinel.raw_keys,
        discovery=sentinel.discovery,
        discovery_account=mock_discovery_account,
        discovery_partition=sentinel.discovery_partition,
        encryption_context=sentinel.raw_encryption_context,
        required_encryption_context_keys=None,
        caching=sentinel.raw_caching,
        action=sentinel.action,
        version=False,
        dummy_redirect=None,
        commitment_policy=CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT,
        buffer=sentinel.buffer_output,
    )
    patch_build_parser.return_value.parse_args.return_value = mock_parsed_args
    test = arg_parsing.parse_args(sentinel.raw_args)

    patch_build_parser.assert_called_once_with()
    patch_build_parser.return_value.parse_args.assert_called_once_with(args=sentinel.raw_args)
    patch_process_wrapping_key_provider_configs.assert_called_once_with(
        sentinel.raw_keys,
        sentinel.action,
    )
    assert test.wrapping_keys is patch_process_wrapping_key_provider_configs.return_value
    patch_process_encryption_context.assert_called_once_with(
        action=sentinel.action,
        raw_encryption_context=sentinel.raw_encryption_context,
        raw_required_encryption_context_keys=None,
    )
    assert test.encryption_context is sentinel.encryption_context
    assert test.required_encryption_context_keys is sentinel.required_keys
    patch_process_caching_config.assert_called_once_with(sentinel.raw_caching)
    assert test.caching is patch_process_caching_config.return_value
    assert test is mock_parsed_args


def test_parse_args_dummy_redirect(
    patch_build_parser,
    patch_process_wrapping_key_provider_configs,
    patch_process_encryption_context,
    patch_process_caching_config,
):
    mock_parsed_args = MagicMock(
        wrapping_keys=sentinel.raw_keys,
        discovery=True,
        encryption_context=sentinel.raw_encryption_context,
        caching=sentinel.raw_caching,
        action=sentinel.action,
        version=False,
        dummy_redirect="-invalid-argument",
    )
    patch_build_parser.return_value.parse_args.return_value = mock_parsed_args
    arg_parsing.parse_args(sentinel.raw_args)

    patch_build_parser.return_value.error.assert_called_once_with(
        'Found invalid argument "-invalid-argument". Did you mean "--invalid-argument"?'
    )


def test_parse_args_no_caching_config(
    patch_build_parser,
    patch_process_wrapping_key_provider_configs,
    patch_process_encryption_context,
    patch_process_caching_config,
):
    patch_build_parser.return_value.parse_args.return_value = MagicMock(caching=None)
    test = arg_parsing.parse_args()

    assert not patch_process_caching_config.called
    assert test.caching is None


def test_parse_args_error_raised_in_post_processing(
    patch_build_parser,
    patch_process_wrapping_key_provider_configs,
    patch_process_encryption_context,
    patch_process_caching_config,
):
    patch_build_parser.return_value.parse_args.return_value = MagicMock(
        version=False, dummy_redirect=None, required_encryption_context_keys=None
    )
    patch_process_caching_config.side_effect = ParameterParseError

    arg_parsing.parse_args()

    patch_build_parser.return_value.error.assert_called_once_with()


@pytest.mark.parametrize(
    "action, raw_encryption_context, raw_required_keys, expected_encryption_context, expected_required_keys",
    (
        ("encrypt", None, None, {}, []),
        ("decrypt", None, None, {}, []),
        ("decrypt-unsigned", None, None, {}, []),
        ("encrypt", ["encryption=context", "with=values"], None, {"encryption": "context", "with": "values"}, []),
        ("decrypt", ["encryption=context", "with=values"], None, {"encryption": "context", "with": "values"}, []),
        (
            "decrypt-unsigned",
            ["encryption=context", "with=values"],
            None,
            {"encryption": "context", "with": "values"},
            [],
        ),
        (
            "encrypt",
            ["encryption=context", "with=values"],
            ["key_1", "key_2"],
            {"encryption": "context", "with": "values"},
            ["key_1", "key_2"],
        ),
        (
            "decrypt",
            ["encryption=context", "with=values"],
            ["key_1", "key_2"],
            {"encryption": "context", "with": "values"},
            ["key_1", "key_2"],
        ),
        (
            "decrypt",
            ["encryption=context", "with=values", "key_3"],
            ["key_1", "key_2"],
            {"encryption": "context", "with": "values"},
            ["key_1", "key_2", "key_3"],
        ),
        (
            "decrypt-unsigned",
            ["encryption=context", "with=values"],
            ["key_1", "key_2"],
            {"encryption": "context", "with": "values"},
            ["key_1", "key_2"],
        ),
        (
            "decrypt-unsigned",
            ["encryption=context", "with=values", "key_3"],
            ["key_1", "key_2"],
            {"encryption": "context", "with": "values"},
            ["key_1", "key_2", "key_3"],
        ),
    ),
)
def test_process_encryption_context(
    action, raw_encryption_context, raw_required_keys, expected_encryption_context, expected_required_keys
):
    test_encryption_context, test_required_keys = arg_parsing._process_encryption_context(
        action, raw_encryption_context, raw_required_keys
    )

    assert test_encryption_context == expected_encryption_context
    assert test_required_keys == expected_required_keys


def test_process_encryption_context_encrypt_required_key_fail():
    with pytest.raises(ParameterParseError):
        arg_parsing._process_encryption_context(
            action="encrypt",
            raw_encryption_context=["encryption=context", "with=values", "key_3"],
            raw_required_encryption_context_keys=["key_1", "key_2"],
        )


@pytest.mark.parametrize(
    "argstring",
    (
        "--decrypt --input - -S --output - -w provider=ex_p_1 key=exkey discovery=1 discovery-account=123",
        "--decrypt --input - -S --output - -w provider=ex_p_1 key=exkey discovery=1 discovery-partition=aws",
        "--decrypt --input - -S --output - -w provider=ex_p_1 key=exkey discovery=0 discovery-account=123",
        "--decrypt --input - -S --output - -w provider=ex_p_1 key=exkey discovery=0 discovery-partition=aws",
        "--decrypt --input - -S --output - -w provider=ex_pr_1 key=exkey discovery=0 discovery-partition=aws"
        "--decrypt-unsigned --input - -S --output - -w provider=ex_p_1 key=exkey discovery=1 discovery-account=123",
        "--decrypt-unsigned --input - -S --output - -w provider=ex_p_1 key=exkey discovery=1 discovery-partition=aws",
        "--decrypt-unsigned --input - -S --output - -w provider=ex_p_1 key=exkey discovery=0 discovery-account=123",
        "--decrypt-unsigned --input - -S --output - -w provider=ex_p_1 key=exkey discovery=0 discovery-partition=aws",
        "--decrypt-unsigned --input - -S --output - -w provider=ex_pr_1 key=exkey discovery=0 discovery-partition=aws"
        " --discovery-account=123",
    ),
)
def test_invalid_discovery(argstring):
    with pytest.raises(SystemExit) as excinfo:
        arg_parsing.parse_args(shlex.split(argstring))

    assert excinfo.value.args == (2,)


def test_discovery_bool():
    assert arg_parsing.discovery_pseudobool("true") is True
    assert arg_parsing.discovery_pseudobool("1") is True
    assert arg_parsing.discovery_pseudobool(True) is True
    assert arg_parsing.discovery_pseudobool("false") is False
    assert arg_parsing.discovery_pseudobool("0") is False
    assert arg_parsing.discovery_pseudobool(False) is False

    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing.discovery_pseudobool(None)
    excinfo.match("Value .* could not be parsed as true or false")


@pytest.mark.parametrize(
    "parsed_args",
    [
        {"discovery-account": ["123"]},
        {"discovery-partition": "aws"},
        {"discovery-account": ["123"], "discovery-partition": "aws"},
        {"discovery": "false", "discovery-account": ["123"]},
        {"discovery": "false", "discovery-partition": "aws"},
        {"discovery": "false", "discovery-account": ["123"], "discovery-partition": "aws"},
        {"discovery": "true", "discovery-account": ["123"]},
        {"discovery": "true", "discovery-partition": "aws"},
    ],
)
def test_process_discovery_args_invalid(parsed_args):
    with pytest.raises(ParameterParseError):
        arg_parsing._process_discovery_args(parsed_args)


def test_process_discovery_args_no_discovery_encrypt():
    parsed_args = {"key": ["foo"]}
    arg_parsing._process_discovery_args(parsed_args)
    assert not parsed_args["discovery"]


def test_process_discovery_args_discovery_true_no_filter():
    parsed_args = {"provider": "aws-kms", "discovery": "true"}
    arg_parsing._process_discovery_args(parsed_args)
    assert parsed_args["discovery"]


def test_process_discovery_args_discovery_true_with_filter():
    parsed_args = {
        "provider": "aws-kms",
        "discovery": "true",
        "discovery-account": ["123"],
        "discovery-partition": ["aws"],
    }
    arg_parsing._process_discovery_args(parsed_args)
    assert parsed_args["discovery"]
    assert parsed_args["discovery-account"] == ["123"]
    assert parsed_args["discovery-partition"] == "aws"


def test_process_discovery_args_discovery_empty_accounts_list():
    parsed_args = {
        "provider": "aws-kms",
        "discovery": "true",
        "discovery-account": [],
        "discovery-partition": ["aws"],
    }
    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing._process_discovery_args(parsed_args)
    excinfo.match(r"When specifying discovery-partition, you must also specify discovery-account")


def test_process_discovery_args_discovery_empty_account():
    parsed_args = {
        "provider": "aws-kms",
        "discovery": "true",
        "discovery-account": ["123", ""],
        "discovery-partition": ["aws"],
    }
    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing._process_discovery_args(parsed_args)
    excinfo.match(r"Value passed to discovery-account cannot be empty")


def test_process_discovery_args_discovery_empty_partition():
    parsed_args = {
        "provider": "aws-kms",
        "discovery": "true",
        "discovery-account": ["123"],
        "discovery-partition": [""],
    }
    with pytest.raises(ParameterParseError) as excinfo:
        arg_parsing._process_discovery_args(parsed_args)
    excinfo.match(r"Value passed to discovery-partition cannot be empty")
