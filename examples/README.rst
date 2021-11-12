#########################################
AWS Encryption CLI Examples
#########################################

This section features examples that show you
how to use the AWS Encryption CLI
We demonstrate how to use the encryption and decryption APIs
and how to set up some common configuration patterns.

Use Cases
=========

* `Encrypt a file <./bin/encrypt_file.sh>`_ and `decrypt it <./bin/decrypt_file.sh>`__.
* `Encrypt all files in a directory <./bin/encrypt_directory.sh>`_ and `decrypt them <./bin/decrypt_directory.sh>`_.
* `Encrypt plaintext from stdin <./bin/encrypt_command_line.sh>`_ and `decrypt from stdin <./bin/decrypt_command_line.sh>`_.
* `Encrypt a file under multiple master keys <./bin/encrypt_file_multiple_keys.sh>`_ and `decrypt it <./bin/decrypt_file_multiple_keys.sh>`__.

See the `Public Documentation <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/crypto-cli-examples.html>`_ for more details on these examples.


Running the examples
====================

In order to run these examples, these things must be configured:

#. Ensure that AWS credentials are available in one of the `automatically discoverable credential locations`_.
#. The following environment variables must be set to a valid `AWS KMS CMK ARN`_ that can be used by the available credentials:

   * ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID``
   * ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID_2``

.. _automatically discoverable credential locations: http://boto3.readthedocs.io/en/latest/guide/configuration.html
.. _AWS KMS CMK ARN: http://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
