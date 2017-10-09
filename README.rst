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
in the destination directory, the string ``.encrypted`` is appended to the destination
filename.  This suffix is also added to all discovered files if recursively encrypting
a directory.  To complement this behavior, in these situations on decrypt, a decryption
suffix of ``.decrypted`` is added to the destination filename.

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


If operating from a directory to a directory, the entire tree of the source directory
is replicated in the target directory.

Providing Parameter Values
--------------------------
Some arguments accept additional parameter values.  These values must be provided in the
form of ``parameter=value`` as demonstrated below.

.. code-block:: sh

   --encryption-context key1=value1 key2=value2 key3=value3
   --master-keys provider=aws-kms key=$KEY_ID_1 key=$KEY_ID_2
   --caching capacity=3 max_age=80.0


Encryption Context
------------------
The `encryption context`_ is an optional, but recommended, set of key-value pairs that contain
arbitrary nonsecret data. The encryption context can contain any data you choose, but it
typically consists of data that is useful in logging and tracking, such as data about the file
type, purpose, or ownership.

Parameters may be provided using the "parameter=value" format defined elsewhere.

.. code-block:: sh

   --encryption-context key1=value1 key2=value2 key3=value3


Master Key Provider Configuration
---------------------------------
Information for configuring a master key provider must be provided.

Parameters may be provided using the "parameter=value" format defined elsewhere.

Required parameters:

* **provider** *(default: aws-kms)* : Indicator of the master key provider to use.

    * See **Advanced Configuration** for more information on using other master key providers.

* **key** *(one required, many allowed)* : Identifier for a master key to be used. Must be an
  identifier understood by the specified master key provider.

    * If using ``aws-kms`` to decrypt, it is not required to supply any key identifier.

Any additional parameters supplied are collected into lists by parameter name and
passed to the master key provider class when it is instantiated.

Multiple master key providers can be defined by using multiple instances of the ``key``
argument.

If multiple master key providers are defined, the first one is treated as the primary.

If multiple master keys are defined in the primary master key provider, the first one is treated as the primary.

.. code-block:: python

   # With parameters:
   --master-keys provider=aws-kms key=$KEY_ARN_1 key=$KEY_ARN_2 region_names=us-west-2 region_names=eu-central-1

   # KMSMasterKeyProvider is called as:
   key_provider = KMSMasterKeyProvider(region_names=['us-west-2', 'eu-central-1'])
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
   --master-keys provider=aws-kms key=$ALIAS_NAME region_names=us-west-2
   --master-keys provider=aws-kms key=$ALIAS_NAME region_names=eu-central-1

AWS KMS Configuration
`````````````````````
If you want to use the ``aws-kms`` master key provider, you can either specify that
as the provider or simply not specify a provider and allow the default value to be used.

There are some configuration options which are unique to the ``aws-kms`` master key provider:

* **profile** : Providing this configuration value will use the specified `named profile`_ credentials.
* **region** : This allows you to specify the target region. If you provide both ``region`` and ``region_names``
   values, ``region_names`` values will be discarded and ``region`` values will be used instead.

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


Caching Configuration
---------------------
Data key caching is optional, but if used then the parameters noted as required must
be provided.  For detailed information about using data key caching with the AWS
Encryption SDK, see the `data key caching documentation`_.

Parameters may be provided using the "parameter=value" format defined elsewhere.

Allowed parameters:

* **capacity** *(required)* : Number of entries that the cache will hold.
* **max_age** *(required)* :  Determines how long each entry can remain in the cache, beginning when it was added.
* **max_messages_encrypted** :  Determines how long each entry can remain in the cache, beginning when it was added.
* **max_bytes_encrypted** : Specifies the maximum number of bytes that a cached data key can encrypt.


Logging and Verbosity
---------------------
The ``-v`` argument allows you to tune the verbosity of the built-in logging to your desired level.
In short, the more ``-v`` arguments you supply, the more verbose the output gets.

* default : aws-encryption-sdk-cli logs all warnings, all dependencies only log critical messages
* ``-v`` :  aws-encryption-sdk-cli performs moderate logging, all dependencies only log critical messages
* ``-vv`` :  aws-encryption-sdk-cli performs detailed logging, all dependencies only log critical messages
* ``-vvv`` :  aws-encryption-sdk-cli performs detailed logging, all dependencies perform moderate logging
* ``-vvvv`` :  aws-encryption-sdk-cli performs detailed logging, all dependencies perform detailed logging


Configuration Files
-------------------
As with any CLI where the configuration can get rather complex, you might want to use a configuration
file to define some or all of your desired behavior.

Configuration files are supported using Python's native `argparse file support`_, which allows
you to write configuration files exactly as you would enter arguments in the shell. Configuration
file references passed to ``aws-crypto`` are identified by the ``@`` prefix and the contents are
expanded as if you had included them in line.

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
similarly place my caching configuration in a configuration file (``caching.conf`` in this example
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

Encoding Output
---------------
If you want to output to ``stdout``, chances are good that you might want to encode that output.
Rather than complicating this tool's interface with encoding, we recommend leveraging native
encoding on your platform by piping the output into an encoder.

Linux/OSX
`````````
For OSX and most Linux distributions, the ``base64`` utility is natively available.

.. code-block:: sh

   aws-crypto -e -o - -i $INPUT_FILE .... | base64


Windows (Powershell)
````````````````````
While there is no native base64 encoder utility in Windows, one is easily obtainable
for the Powershell command line environment through the `Carbon`_ tool suite.

.. code-block:: sh

   aws-crypto -e -o - -i $INPUT_FILE .... | ConvertTo-Base64


Execution
=========

.. code-block:: sh

   usage: aws-crypto [-h] (--version | [-e | -d]
                     [-m MASTER_KEYS [MASTER_KEYS ...]]
                     [-C CACHING [CACHING ...]] -i INPUT -o OUTPUT
                     [-c ENCRYPTION_CONTEXT [ENCRYPTION_CONTEXT ...]]
                     [-a {
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
                     [--interactive] [--no-overwrite] [-r] [-v] [--version]

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
     -C CACHING [CACHING ...], --caching CACHING [CACHING ...]
                           Configuration options for a caching cryptographic
                           materials manager and local cryptographic materials
                           cache. Must consist of "key=value" pairs. If caching,
                           at least "capacity" and "max_age" must be defined. ex:
                           --caching capacity=10 max_age=100.0
     -i INPUT, --input INPUT
                           Input file or directory for encrypt/decrypt operation
                           (default: -)
     -o OUTPUT, --output OUTPUT
                           Output file or directory for encrypt/decrypt operation
                           (default: -)
     -c ENCRYPTION_CONTEXT [ENCRYPTION_CONTEXT ...], --encryption-context ENCRYPTION_CONTEXT [ENCRYPTION_CONTEXT ...]
                           key-value pair encryption context values (encryption
                           only). Must a set of "key=value" pairs. ex: -c
                           key1=value1 key2=value2
     -a {
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
