"""Helper utilities for use while testing examples."""
import os
import platform
import random
import string

AWS_KMS_KEY_ID_1 = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID"
AWS_KMS_KEY_ID_2 = "AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID_2"


def cmk_arn_value(variable_name):
    """Retrieves the target CMK ARN from environment variable."""
    arn = os.environ.get(variable_name, None)
    if arn is None:
        raise ValueError(
            'Environment variable "{}" must be set to a valid KMS CMK ARN for examples to run'.format(
               variable_name 
            )
        )
    if arn.startswith("arn:") and ":alias/" not in arn:
        return arn
    raise ValueError("KMS CMK ARN provided for examples must be a key not an alias")


def cmk_arn():
    return cmk_arn_value(AWS_KMS_KEY_ID_1)


def second_cmk_arn():
    return cmk_arn_value(AWS_KMS_KEY_ID_2)


def is_windows():
    return any(platform.win32_ver())


def setup_file(tmpdir, plaintext):
    """Creates a file in the given tmpdir containing the provided plaintext."""
    filename = ''.join(random.choice(string.ascii_lowercase) for i in range(10))

    full_path = os.path.join(str(tmpdir), filename)
    with open(full_path, "w") as f:
        f.write(plaintext)
    return full_path


def setup_files(tmpdir, num_files):
    """Creates num_files files in the given tmpdir containing random plaintext."""
    files = []
    for i in range(num_files):
        plaintext = ''.join(random.choice(string.ascii_lowercase) for i in range(20))
        filename = setup_file(tmpdir, plaintext)
        files.append(filename)
    return files
