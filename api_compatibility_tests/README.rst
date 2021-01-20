**********************************************
aws-encryption-sdk-cli API Compatibility Tests
**********************************************

Tests that assert the expected behaviour of all `aws-encryption-sdk-cli` versions, released or local.

Execution
=========

.. code-block:: sh

  # Tests all released versions by default.
  AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID=<...> tox

  # Tests a local copy of the aws-encryption-sdk-cli implementation instead.
  # The aws_encryption_sdk_cli.internal.__version__ string must be set accurately for this to work.
  AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID=<...> AWSES_CLI_LOCAL_PATH=<...> tox -e py38-awses_cli_local
