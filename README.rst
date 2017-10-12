######################
aws-encryption-sdk-cli
######################

This command line tool can be used to encrypt and decrypt files and directories using the `AWS Encryption SDK`_.

The latest full documentation can be found at `Read the Docs`_.

Find us on `GitHub`_.

***************
Getting Started
***************

Required Prerequisites
======================

* Python 2.7+ or 3.4+
* aws-encryption-sdk >= 1.3.0

Installation
============

.. note::

   If you have not already installed `cryptography`_, you might need to install additional prerequisites as
   detailed in the `cryptography installation guide`_ for your operating system.

   .. code::

       $ pip install aws-encryption-sdk-cli

*****
Usage
*****

Input and Output
================

For the most part, the behavior of ``aws-crypto`` in handling files is based on that of
GNU CLIs such as ``cp``.  A qualifier to this is that when encrypting a file, if a
directory is provided as the destination, rather than creating the source filename
in the destination directory, a suffix is appended to the destination filename. By
default the suffix is ``.encrypted`` when encrypting and ``.decrypted`` when decrypting,
but a custom suffix can be provided by the caller if desired.

If a destination file already exists, the contents will be overwritten.

.. table::

    +------------------------------+---------------------------------------+
    | **Allowed input/output       | **output**                            |
    | pairings**                   +------------+----------+---------------+
    |                              | **stdout** | **file** | **directory** |
    +-----------+------------------+------------+----------+---------------+
    | **input** |   **stdin**      | Y          | Y        |               |
    |           +------------------+------------+----------+---------------+
    |           |  **single file** | Y          | Y        | Y             |
    |           +------------------+------------+----------+---------------+
    |           | **pattern match**|            |          | Y             |
    |           +------------------+------------+----------+---------------+
    |           |   **directory**  |            |          | Y             |
    +-----------+------------------+------------+----------+---------------+

If the source includes a directory and the ``--recursive`` flag is set, the entire
tree of the source directory is replicated in the target directory.

.. _parameter-values:

Parameter Values
----------------
Some arguments accept additional parameter values.  These values must be provided in the
form of ``parameter=value`` as demonstrated below.

.. code-block:: sh

   --encryption-context key1=value1 key2=value2 "key 3=value with spaces"
   --master-keys provider=aws-kms key=$KEY_ID_1 key=$KEY_ID_2
   --caching capacity=3 max_age=80.0


.. _encryption-context:

Encryption Context
------------------
The `encryption context`_ is an optional, but recommended, set of key-value pairs that contain
arbitrary nonsecret data. The encryption context can contain any data you choose, but it
typically consists of data that is useful in logging and tracking, such as data about the file
type, purpose, or ownership.

Parameters may be provided using :ref:`parameter-values`.

.. code-block:: sh

   --encryption-context key1=value1 key2=value2 "key 3=value with spaces"


.. _master-key-provider:

Master Key Provider
-------------------
Information for configuring a master key provider must be provided.

Parameters may be provided using :ref:`parameter-values`.

Required parameters:

* **provider** *(default: aws-kms)* : Indicator of the master key provider to use.

    * See :ref:`advanced-configuration` for more information on using other master key providers.

* **key** *(one required, many allowed)* : Identifier for a master key to be used. Must be an
  identifier understood by the specified master key provider.

    * If using ``aws-kms`` to decrypt, it is not necessary to supply any key identifier.

Any additional parameters supplied are collected into lists by parameter name and
passed to the master key provider class when it is instantiated. Custom master key providers
may provide an arguments post-processing function to modify these values before passing
them to the master key provider. See :ref:`advanced-configuration` for more information.

Multiple master keys can be defined using multiple instances of the ``key`` argument.

Multiple master key providers can be defined using multiple ``--master-keys`` groups.

If multiple master key providers are defined, the first one is treated as the primary.

If multiple master keys are defined in the primary master key provider, the first one is treated
as the primary. This master key is used to generate the data key.

.. code-block:: python

   # With parameters:
   --master-keys provider=aws-kms key=$KEY_ARN_1 key=$KEY_ARN_2

   # KMSMasterKeyProvider is called as:
   key_provider = KMSMasterKeyProvider()
   key_provider.add_master_key($KEY_ARN_1)
   key_provider.add_master_key($KEY_ARN_2)

.. table::

   +------------------------------------+
   | Known Master Key Providers         |
   +-------------+----------------------+
   | Provider ID | Python callable      |
   +=============+======================+
   | aws-kms     | KMSMasterKeyProvider |
   +-------------+----------------------+


.. code-block:: sh

   # Single KMS CMK
   --master-keys provider=aws-kms key=$KEY_ARN_1

   # Two KMS CMKs
   --master-keys provider=aws-kms key=$KEY_ARN_1 key=$KEY_ARN_2

   # KMS Alias by name in default region
   --master-keys provider=aws-kms key=$ALIAS_NAME

   # KMS Alias by name in two specific regions
   --master-keys provider=aws-kms key=$ALIAS_NAME region=us-west-2
   --master-keys provider=aws-kms key=$ALIAS_NAME region=eu-central-1

.. _aws-kms:

AWS KMS
```````
If you want to use the ``aws-kms`` master key provider, you can either specify that
as the provider or simply not specify a provider and allow the default value to be used.

There are some configuration options which are unique to the ``aws-kms`` master key provider:

* **profile** : Providing this configuration value will use the specified `named profile`_
   credentials.
* **region** : This allows you to specify the target region.

The logic for determining which region to use is shown in the pseudocode below:

.. code-block:: python

   if key ID is an ARN:
      use region identified in ARN
   else:
      if region is specified:
         use region
      else if profile is specified and profile has a defined region:
         use profile's region
      else:
         use system default region

.. _advanced-configuration:

Advanced Configuration
``````````````````````
If you want to use some other master key provider, that provider must be available in
your local ``$PYTHONPATH`` as a callable (class or function) which will return the
desired master key provider when called with the defined parameters. The value that
must be passed to ``aws-crypto`` as the provider parameter is the full Python namespace
path leading to that callable.

For example, if specifying the ``aws-kms`` master key provider using this option,
you would define ``provider=aws_encryption_sdk.KMSMasterKeyProvider``.

If this option is used, the appropriate module will be imported and the callable loaded
and called while building the master key provider.

.. code-block:: sh

   # Single KMS CMK, specifying the KMSMasterKeyProvider class directly
   --master-keys provider=aws_encryption_sdk.KMSMasterKeyProvider key=$KEY_ARN_1


.. _data-key-caching:

Data Key Caching
----------------
Data key caching is optional, but if used then the parameters noted as required must
be provided.  For detailed information about using data key caching with the AWS
Encryption SDK, see the `data key caching documentation`_.

Parameters may be provided using :ref:`parameter-values`.

Allowed parameters:

* **capacity** *(required)* : Number of entries that the cache will hold.
* **max_age** *(required)* :  Determines how long each entry can remain in the cache, beginning when it was added.
* **max_messages_encrypted** :  Determines how long each entry can remain in the cache, beginning when it was added.
* **max_bytes_encrypted** : Specifies the maximum number of bytes that a cached data key can encrypt.


.. _verbosity:

Logging and Verbosity
---------------------
The ``-v`` argument allows you to tune the verbosity of the built-in logging to your desired level.
In short, the more ``-v`` arguments you supply, the more verbose the output gets.

* unset : ``aws-crypto`` logs all warnings, all dependencies only log critical messages
* ``-v`` :  ``aws-crypto`` performs moderate logging, all dependencies only log critical messages
* ``-vv`` :  ``aws-crypto`` performs detailed logging, all dependencies only log critical messages
* ``-vvv`` :  ``aws-crypto`` performs detailed logging, all dependencies perform moderate logging
* ``-vvvv`` :  ``aws-crypto`` performs detailed logging, all dependencies perform detailed logging

.. table::

   +---------------------------------------+
   |       python logging levels           |
   +===========+============+==============+
   | verbosity | aws-crypto | dependencies |
   | flag      |            |              |
   +-----------+------------+--------------+
   | unset     | WARNING    | CRITICAL     |
   +-----------+------------+--------------+
   | -v        | INFO       | CRITICAL     |
   +-----------+------------+--------------+
   | -vv       | DEBUG      | CRITICAL     |
   +-----------+------------+--------------+
   | -vvv      | DEBUG      | INFO         |
   +-----------+------------+--------------+
   | -vvvv     | DEBUG      | DEBUG        |
   +-----------+------------+--------------+


.. _config-files:

Configuration Files
-------------------
As with any CLI where the configuration can get rather complex, you might want to use a configuration
file to define some or all of your desired behavior.

Configuration files are supported using Python's native `argparse file support`_, which allows
you to write configuration files exactly as you would enter arguments in the shell. Configuration
file references passed to ``aws-crypto`` are identified by the ``@`` prefix and the contents are
expanded as if you had included them in line. Configuration files can have any name you desire.

For example, if I wanted to use a common master key configuration for all of my calls, I could
create a file ``master-key.conf`` with contents detailing my master key configuration.

**master-key.conf**

.. code-block:: sh

   --master-key key=SOME_KEY_ARN key=ANOTHER_KEY_ARN

Then, when calling ``aws-crypto``, I can specify the rest of my arguments and reference my new
configuration file, and ``aws-crypto`` will use the composite configuration.

.. code-block:: sh

   aws-crypto -e -i $INPUT_FILE -o $OUTPUT_FILE @master-key.conf


To extend the example, if I wanted a common caching configuration for all of my calls, I could
similarly place my caching configuration in a configuration file ``caching.conf`` in this example
and include both files in my call.

**caching.conf**

.. code-block:: sh

   --caching capacity=10 max_age=60.0 max_messages_encrypted=15

.. code-block:: sh

   aws-crypto -e -i $INPUT_FILE -o $OUTPUT_FILE @master-key.conf @caching.conf

Configuration files can be referenced anywhere in ``aws-crypto`` parameters.

.. code-block:: sh

   aws-crypto -e -i $INPUT_DIR -o $OUTPUT_DIR @master-key.conf @caching.conf --recursive

Configuration files can have many lines, include comments using ``#``, and include
references to other configuration files.

**my-encrypt.config**

.. code-block:: sh

   --encrypt
   @master-key.conf # Use existing master key config
   @caching.conf
   # Always recurse, but require interactive overwrite.
   --recursive
   --interactive

.. code-block:: sh

   aws-crypto @my-encrypt -i $INPUT -o $OUTPUT


Execution
=========

.. code-block:: sh

   usage: aws-crypto [-h] (--version | [-e | -d]
                     [-m MASTER_KEYS [MASTER_KEYS ...]]
                     [--caching CACHING [CACHING ...]] -i INPUT -o OUTPUT
                     [-c ENCRYPTION_CONTEXT [ENCRYPTION_CONTEXT ...]]
                     [--algorithm {
                        AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                        AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
                        AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
                        AES_256_GCM_IV12_TAG16_HKDF_SHA256,
                        AES_192_GCM_IV12_TAG16_HKDF_SHA256,
                        AES_128_GCM_IV12_TAG16_HKDF_SHA256,
                        AES_256_GCM_IV12_TAG16,
                        AES_192_GCM_IV12_TAG16,
                        AES_128_GCM_IV12_TAG16
                     }]
                     [--frame-length FRAME_LENGTH] [--max-length MAX_LENGTH]
                     [--suffix SUFFIX] [--interactive] [--no-overwrite] [-r] [-v]
                     [-q]

   Encrypt or decrypt data using the AWS Encryption SDK

   optional arguments:
     -h, --help            show this help message and exit
     --version             show program's version number and exit
     -e, --encrypt         Encrypt data
     -d, --decrypt         Decrypt data
     -m MASTER_KEYS [MASTER_KEYS ...], --master-keys MASTER_KEYS [MASTER_KEYS ...]
                           Identifying information for a master key provider and
                           master keys. Each instance must include a master key
                           provider identifier and identifiers for one or more
                           master key supplied by that provider. ex: --master-
                           keys provider=aws-kms key=$AWS_KMS_KEY_ARN
     --caching CACHING [CACHING ...]
                           Configuration options for a caching cryptographic
                           materials manager and local cryptographic materials
                           cache. Must consist of "key=value" pairs. If caching,
                           at least "capacity" and "max_age" must be defined. ex:
                           --caching capacity=10 max_age=100.0
     -i INPUT, --input INPUT
                           Input file or directory for encrypt/decrypt operation,
                           or "-" for stdin.
     -o OUTPUT, --output OUTPUT
                           Output file or directory for encrypt/decrypt
                           operation, or - for stdout.
     -c ENCRYPTION_CONTEXT [ENCRYPTION_CONTEXT ...], --encryption-context ENCRYPTION_CONTEXT [ENCRYPTION_CONTEXT ...]
                           key-value pair encryption context values (encryption
                           only). Must a set of "key=value" pairs. ex: -c
                           key1=value1 key2=value2
     --algorithm {
            AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
            AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
            AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256,
            AES_256_GCM_IV12_TAG16_HKDF_SHA256,
            AES_192_GCM_IV12_TAG16_HKDF_SHA256,
            AES_128_GCM_IV12_TAG16_HKDF_SHA256,
            AES_256_GCM_IV12_TAG16,
            AES_192_GCM_IV12_TAG16,
            AES_128_GCM_IV12_TAG16
         }
                           Algorithm name (encryption only)
     --frame-length FRAME_LENGTH
                           Frame length in bytes (encryption only)
     --max-length MAX_LENGTH
                           Maximum frame length (for framed messages) or content
                           length (for non-framed messages) (decryption only)
     --suffix SUFFIX       Custom suffix to use when target filename is not
                           specified
     --interactive         Force aws-crypto to prompt you for verification before
                           overwriting existing files
     --no-overwrite        Never overwrite existing files
     -r, -R, --recursive   Allow operation on directories as input
     -v                    Enables logging and sets detail level. Multiple -v
                           options increases verbosity (max: 4).
     -q, --quiet           Suppresses most warning and diagnostic messages

   For more usage instructions and examples, see: http://aws-encryption-sdk-cli.readthedocs.io/en/latest/


.. _AWS Encryption SDK: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html
.. _Read the Docs: http://aws-encryption-sdk-cli.readthedocs.io/en/latest/
.. _GitHub: https://github.com/awslabs/aws-encryption-sdk-cli/
.. _cryptography: https://cryptography.io/en/latest/
.. _cryptography installation guide: https://cryptography.io/en/latest/installation/
.. _data key caching documentation: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html
.. _encryption context: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
.. _KMSMasterKeyProvider: http://aws-encryption-sdk-python.readthedocs.io/en/latest/generated/aws_encryption_sdk.key_providers.kms.html#aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider
.. _Carbon: https://www.powershellgallery.com/packages/Carbon
.. _argparse file support: https://docs.python.org/3/library/argparse.html#fromfile-prefix-chars
.. _named profile: http://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html
