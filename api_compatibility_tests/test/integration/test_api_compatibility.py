import base64
import json
import os
import platform
import pytest
import shlex

from importlib import metadata
from packaging.specifiers import SpecifierSet
from packaging.version import Version
from subprocess import PIPE, Popen

import aws_encryption_sdk_cli

CLI_VERSION = Version(metadata.version('aws-encryption-sdk-cli'))

pytestmark = [pytest.mark.integ]

AWS_KMS_KEY_ID = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID"

# A fake alternate value for key=... that shouldn't match cmk_arn_value()
OTHER_CMK_ARN_VALUE = "arn:aws:kms:us-west-2:123456789012:key/totally-a-uuid"

def cmk_arn_value():
    """Retrieves the target CMK ARN from environment variable."""
    arn = os.environ.get(AWS_KMS_KEY_ID, None)
    if arn is None:
        raise ValueError(
            'Environment variable "{}" must be set to a valid KMS CMK ARN for integration tests to run'.format(
                AWS_KMS_KEY_ID
            )
        )
    if arn.startswith("arn:") and ":alias/" not in arn:
        return arn
    raise ValueError("KMS CMK ARN provided for integration tests must be a key not an alias")
    

def encrypt_args_template(metadata=False, caching=False, encode=False, decode=False):
    template = "-e -i {source} -o {target} --encryption-context a=b c=d"
    if metadata:
        template += " {metadata}"
    else:
        template += " -S"
    if caching:
        template += " --caching capacity=10 max_age=60.0"
    if encode:
        template += " --encode"
    if decode:
        template += " --decode"
    return template

def decrypt_args_template(metadata=False, encode=False, decode=False):
    template = "-d -i {source} -o {target}"
    if metadata:
        template += " {metadata}"
    else:
        template += " -S"
    if encode:
        template += " --encode"
    if decode:
        template += " --decode"
    return template

def is_windows():
    return any(platform.win32_ver())

# Constants to differentiate the intent when operations success,
# between correct use of the API and incorrect success due to a bug.
SUCCESS = None
SHOULD_HAVE_BEEN_AN_ERROR = None

# Tests of expected behavior (success or specific error content) on decrypt.
# errors_per_version maps from version filters to the expected error message substring
# or one of the None constants above.
# TODO: Another test method for decrypting messages with commitment as well.
# TODO: Similar tests for the --encrypt API.
@pytest.mark.parametrize(
    "decrypt_extra_args,errors_per_version",
    [
        # --wrapping-keys was supposed to be a required argument in 2.0, fixed in 2.1
        # --commmitment-policy also should be scoped to only when using --wrapping-keys (in any version)
        (
            "", 
            {
                "==1.7.0|~=1.8": SUCCESS,
                "==2.0.0      ": 'error: Discovery must be set to True or False',
                "~=2.1|>=3.0  ": 'error: the following arguments are required: -w/--wrapping-keys'
            }
        ),
        (
            "--commitment-policy forbid-encrypt-allow-decrypt", 
            {
                "==1.7.0": SHOULD_HAVE_BEEN_AN_ERROR,
                "~=1.8  ": 'error: Commitment policy is only supported when using the --wrapping-keys parameter',
                "==2.0.0": 'error: Discovery must be set to True or False',
                "~=2.1|>=3.0": 'error: the following arguments are required: -w/--wrapping-keys'
            }
        ),
        (
            "--commitment-policy forbid-encrypt-allow-decrypt --discovery true", 
            {
                "==1.7.0|==2.0.0": SHOULD_HAVE_BEEN_AN_ERROR,
                "~=1.8          ": 'unrecognized arguments: --discovery',
                "~=2.1|>=3.0    ": 'error: the following arguments are required: -w/--wrapping-keys'
            }
        ),
        # discovery-related parameters accidentally implemented in 1.7 and 2.0, removed in 1.8 and 2.1
        (
            "--commitment-policy forbid-encrypt-allow-decrypt  --discovery true --wrapping-keys discovery=true", 
            {
                "==1.7.0|==2.0.0": SHOULD_HAVE_BEEN_AN_ERROR,
                "~=1.8|~=2.1|>=3.0": "unrecognized arguments: --discovery"
            }
        ),
        # discovery filter was also configured through top level parameters and hit an internal error when used :(
        (
            "--commitment-policy forbid-encrypt-allow-decrypt --discovery true --discovery-partition aws --discovery-account 111222333444 --wrapping-keys discovery=true", 
            {
                "==1.7.0|==2.0.0": "TypeError(\"'discovery_filter' must be <class",
                "~=1.8|~=2.1|>=3.0": "unrecognized arguments: --discovery"
            }
        ),
        # Disabling discovery on wrapping keys was accepted but non-functional in 1.7 and 2.0, fixed in 1.8 and 2.1
        (
            "--commitment-policy forbid-encrypt-allow-decrypt --wrapping-keys key=" + OTHER_CMK_ARN_VALUE, 
            {
                "==1.7.0    ": 'error: Exact wrapping keys cannot be specified for aws-kms wrapping key provider on decrypt in discovery mode',
                "==2.0.0    ": 'error: Discovery must be set to True or False',
                "~=1.8|~=2.1|>=3.0": 'DecryptKeyError("Unable to decrypt any data key")'
            }
        ),
        (
            "--commitment-policy forbid-encrypt-allow-decrypt --discovery false --wrapping-keys key=" + OTHER_CMK_ARN_VALUE, 
            {
                "==1.7.0|==2.0.0": SHOULD_HAVE_BEEN_AN_ERROR,
                "~=1.8  |~=2.1|>=3.0": 'unrecognized arguments: --discovery'
            }
        ),
        # --commitment-policy should have been required in 1.7 when using --wrapping-keys, fixed in 1.8
        (
            "--wrapping-keys discovery=true", 
            {
                "==1.7.0": SHOULD_HAVE_BEEN_AN_ERROR,
                "~=1.8  ": 'error: Commitment policy is required when specifying the --wrapping-keys parameter',
                "==2.0.0": 'error: Discovery must be set to True or False',
                "~=2.1|>=3.0": 'Cannot decrypt due to CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT requiring only committed messages'
            }
        ),
    ]
)
def test_encrypt_decrypt_roundtrip(tmpdir, decrypt_extra_args, errors_per_version):
    ciphertext_file = tmpdir.join("ciphertext")
    plaintext = os.urandom(1024)

    encrypt_args = "aws-encryption-cli " + encrypt_args_template(decode=True).format(
        source="-", target=str(ciphertext_file)
    ) + " --commitment-policy forbid-encrypt-allow-decrypt --wrapping-keys key=" + cmk_arn_value()
    
    proc = Popen(shlex.split(encrypt_args, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    _stdout, stderr = proc.communicate(input=base64.b64encode(plaintext))
    assert proc.returncode == 0, "Unexpected error:\n" + stderr.decode("utf-8")

    decrypt_args = "aws-encryption-cli " + decrypt_args_template(encode=True).format(
        source=str(ciphertext_file), target="-"
    ) + " " + decrypt_extra_args

    proc = Popen(shlex.split(decrypt_args, posix=not is_windows()), stdout=PIPE, stdin=PIPE, stderr=PIPE)
    decrypted_stdout, stderr = proc.communicate()

    for specifiers, error_message in errors_per_version.items():
        if any(CLI_VERSION in SpecifierSet(specifier) for specifier in specifiers.split("|")):
            if error_message:
                assert proc.returncode != 0
                assert error_message in stderr.decode("utf-8")
                return
            else:
                assert proc.returncode == 0, "Unexpected error:\n" + stderr.decode("utf-8")
                assert base64.b64decode(decrypted_stdout) == plaintext
                return
    assert False, "No specifiers matched version " + CLI_VERSION + " for test case"
                