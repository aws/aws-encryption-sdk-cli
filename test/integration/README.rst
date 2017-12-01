****************************************
aws-encryption-sdk-cli Integration Tests
****************************************

In order to run these integration tests successfully, these things which must be configured.

#. These tests assume that AWS credentials are available in one of the
   `automatically discoverable credential locations`_.
#. The ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_CONTROL`` environment variable must be set to ``RUN``.
#. The ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID`` environment variable must be set to
   a valid `AWS KMS key id`_ that can be used by the available credentials.

.. _automatically discoverable credential locations: http://boto3.readthedocs.io/en/latest/guide/configuration.html
.. _AWS KMS key id: http://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
