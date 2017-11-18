######################
aws-encryption-sdk-cli
######################

You can use this command line version of the `AWS Encryption SDK`_ to encrypt and 
decrypt the data in your files and directories.

You can find the latest full documentation at `Read the Docs`_.

Find us on `GitHub`_.

***************
Getting Started
***************

Required Prerequisites
======================

* Python 2.7+ or 3.4+
* aws-encryption-sdk >= 1.3.2

Installation
============

.. note::

   If you have not already installed `cryptography`_, you might need to install
   additional prerequisites. For details, see  the `cryptography installation guide`_ 
   for your operating system.

   .. code::

       $ pip install aws-encryption-sdk-cli

*****
Usage
*****

Input and Output
================

In general, the ``aws-encryption-cli`` handles files like GNU CLIs, such as ``cp``.  
However, when the output location is a directory, instead of creating a file in the
output directory with the same name as the file in the input directory, the 
``aws-encryption-cli``it appends a suffix to the filename. By default, the suffix is
``.encrypted`` when encrypting and ``.decrypted`` when decrypting, but you can specify 
a custom suffix.

If a destination file already exists, the ``aws-encryption-cli`` overwrites the contents
by default.

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

If the source includes a directory and the ``--recursive`` parameter is specified, 
the ``aws-encryption-cli`` replicates the entire source tree in the output directory.

Parameter Values
----------------
Some ``aws-encryption-cli`` parameters take arguments with a 
``key=value`` format, as shown below. 

.. code-block:: sh

   --encryption-context key1=value1 key2=value2 "key 3=value with spaces"
   --master-keys provider=aws-kms key=$KEY_ID_1 key=$KEY_ID_2
   --caching capacity=3 max_age=80.0


Encryption Context
------------------

Encrypt
```````

The `encryption context`_ is an optional, but recommended, set of key-value pairs that contain
arbitrary nonsecret data. The encryption context can contain any data you choose, but it
typically consists of data that is useful in logging and tracking, such as data about the file
type, purpose, or ownership.

The `encryption context`_ parameter arguments have a ``key=value`` format.

.. code-block:: sh

   --encryption-context key1=value1 key2=value2 "key 3=value with spaces"

Decrypt
```````

If you provide an encryption context on decrypt, the ``aws-encryption-cli`` requires that 
the message being decrypted was encrypted using an encryption context that matches the 
specified requirements.

If you provide ``key=value`` pairs, the ``aws-encryption-cli`` will decrypt only continue 
if the encryption context in the encrypted message contains matching pairs.

.. code-block:: sh

   --encryption-context required_key=required_value classification=secret

If you provide ``key`` elements without values , the ``aws-encryption-cli`` will decrypt only
if those keys are found, regardless of the values. You can mix ``key`` and ``key=value`` 
elements in the same parameter value.

.. code-block:: sh

   --encryption-context required_key classification=secret

.. warning::

   If encryption context requirements are not satisfied by the encrypted message, the
   ``aws-encryption-cli`` will not decrypt the message. One side effect of this features is 
   that if you chose to write the plaintext output to a file that already exists, the 
   command will be deleted when
   we stop the decryption.
   
   If the encrypted message does not satisfy the encryption context requirements, the
   ``aws-encryption-cli`` will not decrypt the message. One side effect of this process
   is that if the output location is an existing file, the file is deleted.

Output Metadata
---------------
In addition to the primary output of the operation, the commands generate useful metadata 
about the encrypt and decrypt operation. This metadata includes information about the 
operation as well as the complete header data from the encrypted message.

The ``aws-encryption-cli`` writes the metadata for each operation is written to the specified 
file as a single line containing formatted JSON. When a command performs multiple file operations, 
the ``aws-encryption-cli`` writes a separate line for each operation. 

There are three operating modes:

* ``--metadata-output FILE`` : Writes the metadata output to ``FILE`` (can be ``-`` for stdout
  as long as primary output is not stdout). By default, the ``aws-encryption-cli`` appends the 
  metadata entry to the end of ``FILE``.
* ``--overwrite-metadata`` : Force the ``aws-encryption-cli`` to overwrite the contents of 
``FILE`` with the new metadata.
* ``-S/--suppress-metadata`` : Suppresses the metadata.

Metadata Contents
`````````````````
The metadata JSON contains the following fields:

* ``"mode"`` : ``"encrypt"``/``"decrypt"``
* ``"input"`` : Full path to the input file (or ``"<stdin>"`` if stdin)
* ``"output"`` : Full path to the output file (or ``"<stdout>"`` if stdout)
* ``"header"`` : JSON representation of `message header data`_
* ``"header_auth"`` : JSON representation of `message header authentication data`_ (only on decrypt)

Skipped Files
~~~~~~~~~~~~~
If encryption context checks fail when the ``aws-encryption-cli`` is decrypting a file, the 
metadata contains the following additional fields:

* ``skipped`` : ``true``
* ``reason`` : ``"Missing encryption context key or value"``
* ``missing_encryption_context_keys`` : List of required encryption context keys that were
  missing from the message.
* ``missing_encryption_context_pairs`` : List of required encryption context key-value pairs
  missing from the message.


Master Key Provider
-------------------
You must provide information about your master key provider.

Parameters may be provided using `Parameter Values`_.
The parameter values are formatted as ``key=value`` pairs.

Required parameters:

* **provider** *(default: aws-encryption-sdk-cli::aws-kms)* : Indicates the master key
  provider to use.

    * See `Advanced Configuration`_ for more information about using other master key providers.

* **key** *(one required, many allowed)* : Identifies the master key to be used.
  Must be an identifier understood by the specified master key provider.

    * If using ``aws-kms`` to decrypt, `you must not specify a key`_.

The ``aws-encryption-cli`` collects any additional parameters into lists by parameter name and
passes them to the master key provider class when it is instantiated. Custom master key providers
must accept all arguments as prepared. See `Advanced Configuration`_ for more information.

To specify multiple master keys, you can use multiple instances of the ``key`` argument or 
define multiple ``--master-keys`` groups.

If you specify multiple master key providers, the first master key provider is treated as the primary.

If you specify multiple master keys for the primary master key provider, the first master key is treated
as the primary. The primary master key is used to generate the data key.

The following logic is used to construct all master key providers. We use ``KMSMasterKeyProvider``
as an example.

.. code-block:: python

   # With parameters:
   --master-keys provider=aws-kms key=$KEY_1 key=$KEY_2

   # KMSMasterKeyProvider is called as:
   key_provider = KMSMasterKeyProvider()
   key_provider.add_master_key($KEY_1)
   key_provider.add_master_key($KEY_2)

.. code-block:: sh

   # Single KMS CMK
   --master-keys provider=aws-kms key=$KEY_ARN_1

   # Two KMS CMKs
   --master-keys provider=aws-kms key=$KEY_ARN_1 key=$KEY_ARN_2

   # KMS alias name in default AWS Region
   --master-keys provider=aws-kms key=$ALIAS_NAME

   # KMS alias name in two AWS Regions
   --master-keys provider=aws-kms key=$ALIAS_NAME region=us-west-2
   --master-keys provider=aws-kms key=$ALIAS_NAME region=eu-central-1

AWS KMS
```````
If you want to use the ``aws-kms`` master key provider, you can either specify ``aws-kms``
as the provider or do not specify a provider and allow the default value to be used.

You can use the following configuration options only with the ``aws-kms`` master key provider:

* **profile** : ``aws-encryption-cli`` uses the specified `named profile`_
  credentials.
* **region** : Specifies the target region.

The following logic determines which region to use:

.. code-block:: python

   if key ID is a CMK ARN:
      use region in the ARN
   else:
      if region is specified:
         use region
      else if profile is specified and profile has a defined region:
         use region defined in profile
      else:
         use system default region

Advanced Configuration
``````````````````````
If you want to use a different master key provider, that provider must register a
`setuptools entry point`_. You can find an example of registering this entry point in the
``setup.py`` for this package.

When you specify a provider name a call to ``aws-encryption-cli``, the appropriate entry
point for that name is used.

Handling Multiple Entry Points
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If multiple entry points are registered for a given name, you need to specify the package
that registered the entry point you want to use.

To specify the package name, use the format: ``PACKAGE_NAME::ENTRY_POINT``.


* ``provider=aws-kms``
* ``provider=aws-encryption-sdk-cli::aws-kms``

If you supply only an entry point name and there is only one entry point registered for that
name, the ``aws-encryption-cli`` will use that entry point.

If you supply only an entry point name and there is more than one entry point registered
for that name, the ``aws-encryption-cli`` will raise an error listing all of the packages 
that have an entry point registered for that name.

If you supply both a package and an entry point name, that exact entry point will be used.
If it is not accessible, the ``aws-encryption-cli`` raises an error listing the packages that have
an entry point registered for that name.

External Master Key Providers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The entry point name use must not contain the string ``::``. This is used as a namespace
separator, as descibed in `Handling Multiple Entry Points`_.

When called, these entry points must return an instance of a master key provider. They must
accept the parameters prepared by the CLI as described in `Master Key Provider`_.

These entry points must be registered in the ``aws_encryption_sdk_cli.master_key_providers``
group.

If the entry point raises a ``aws_encryption_sdk_cli.exceptions.BadUserArgumentError``, the
CLI displays the raised error message to the user to indicate bad user input.

Data Key Caching
----------------
Data key caching is optional, but if you use it, you must provide values for the required 
parameters. For detailed information about using data key caching with the AWS Encryption SDK, 
see the `data key caching documentation`_.

The `data key caching`_ parameter arguments have a ``key=value`` format.

Parameters may be provided using `Parameter Values`_.

Data key caching parameter attributes:

* **capacity** *(required)* : Number of entries that the cache will hold.
* **max_age** *(required)* :  Determines how long each entry can remain in the cache, beginning when it was added.
* **max_messages_encrypted** :  Determines how long each entry can be used, beginning when it was added.
* **max_bytes_encrypted** : Specifies the maximum number of bytes that a cached data key can encrypt.


Logging and Verbosity
---------------------
The ``-v`` argument allows you to tune the verbosity of the built-in logging to your desired level.
The more ``-v`` arguments you supply, the more verbose the output gets.

* unset : ``aws-encryption-cli`` logs all warnings. Dependencies log only log critical messages.
* ``-v`` :  ``aws-encryption-cli`` performs moderate logging. Dependencies log only critical messages.
* ``-vv`` :  ``aws-encryption-cli`` performs detailed logging. Dependencies log only critical messages.
* ``-vvv`` :  ``aws-encryption-cli`` performs detailed logging. Dependencies perform moderate logging.
* ``-vvvv`` :  ``aws-encryption-cli`` performs detailed logging. Dependencies perform detailed logging.

.. table::

   +-----------------------------------------------+
   |           python logging levels               |
   +===========+====================+==============+
   | verbosity | aws-encryption-cli | dependencies |
   | flag      |                    |              |
   +-----------+--------------------+--------------+
   | unset     | WARNING            | CRITICAL     |
   +-----------+--------------------+--------------+
   | -v        | INFO               | CRITICAL     |
   +-----------+--------------------+--------------+
   | -vv       | DEBUG              | CRITICAL     |
   +-----------+--------------------+--------------+
   | -vvv      | DEBUG              | INFO         |
   +-----------+--------------------+--------------+
   | -vvvv     | DEBUG              | DEBUG        |
   +-----------+--------------------+--------------+


Configuration Files
-------------------
As with any CLI where the configuration can get rather complex, you might want to use a configuration
file to define some or all of your desired behavior.

Configuration files are supported by using Python's native `argparse file support`_, which allows
you to write configuration files exactly as you would enter arguments in the shell. 

To pass configuration file references to the ``aws-encryption-cli``, prefix the file name with ``@``. The
configuration file contents are expanded as if you had included them in line. Configuration files can have any
name you desire.

.. note::

   In PowerShell, you need to escape the ``@`` symbol (`@) so that the configuration file reference 
   is sent to ``aws-encryption-cli`` and not interpreted by PowerShell.

For example, if I wanted to use a common master key configuration for all of my commands, I could
create a file ``master-key.conf`` that contains the parameters and parameter values that describe 
my master key configuration.

**master-key.conf**

.. code-block:: sh

   --master-key key=A_KEY key=ANOTHER_KEY

Then, when calling ``aws-encryption-cli``, I can specify the rest of my arguments and reference
my new configuration file. The ``aws-encryption-cli`` will use the composite configuration.

.. code-block:: sh

   aws-encryption-cli -e -i $INPUT_FILE -o $OUTPUT_FILE --metadata-output $METADATA_FILE @master-key.conf


To extend the example, if I wanted a common caching configuration for all of my calls, I could
similarly place my caching configuration in a configuration file ``caching.conf`` in this example
and include both files in my call.

**caching.conf**

.. code-block:: sh

   --caching capacity=10 max_age=60.0 max_messages_encrypted=15

.. code-block:: sh

   aws-encryption-cli -e -i $INPUT_FILE -o $OUTPUT_FILE --metadata-output $METADATA_FILE @master-key.conf @caching.conf

You can reference configuration files anywhere in ``aws-encryption-cli`` parameters.

.. code-block:: sh

   aws-encryption-cli -e -i $INPUT_DIR -o $OUTPUT_DIR @master-key.conf @caching.conf --recursive --metadata-output $METADATA_FILE

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

   aws-encryption-cli @my-encrypt -i $INPUT -o $OUTPUT


Encoding
--------
By default, ``aws-encryption-cli`` will always output raw binary data and expect raw binary data
as input. However, there are some cases where you might not want this to be the case.

Sometimes this might be for convenience:

* Accepting ciphertext through stdin from a human.
* Presenting ciphertext through stdout to a human.

Sometimes it might be out of necessity:

* Saving ciphertext output to a shell variable.

   * Most shells apply a system encoding to any data stored in a variable. As a result, this
     often results in corrupted data if binary data is stored without additional encoding.

* Piping ciphertext in PowerShell.

   * Similar to the above, all data passed through a PowerShell pipe is encoded using the
     system encoding.

In order to address these scenarios, we provide two optional arguments:

* ``--decode`` : Base64-decode input before processing.
* ``--encode`` : Base64-encode output after processing.

You can use them independently or together on any valid input or output.

Be aware, however, that if you are encrypting or decrypting multiple files, all of the 
files are encoded and decoded.


Execution
=========

.. code-block:: sh

   usage: aws-encryption-cli [-h] [--version] [-e] [-d] [-S]
                     [--metadata-output METADATA_OUTPUT] [--overwrite-metadata]
                     [-m MASTER_KEYS [MASTER_KEYS ...]]
                     [--caching CACHING [CACHING ...]] -i INPUT -o OUTPUT
                     [--encode] [--decode]
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
                     [--suffix [SUFFIX]] [--interactive] [--no-overwrite] [-r]
                     [-v] [-q]

   Encrypt or decrypt data using the AWS Encryption SDK

   optional arguments:
     -h, --help            show this help message and exit
     --version             show program's version number and exit
     -e, --encrypt         Encrypt data
     -d, --decrypt         Decrypt data
     -S, --suppress-metadata
                           Suppress metadata output.
     --metadata-output METADATA_OUTPUT
                           File to write metadata records
     --overwrite-metadata  Force metadata output to overwrite contents of file
                           rather than appending to file
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
     --encode              Base64-encode output after processing
     --decode              Base64-decode input before processing
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
     --suffix [SUFFIX]     Custom suffix to use when target filename is not
                           specified (empty if specified but no value provided)
     --interactive         Force aws-encryption-cli to prompt you for verification before
                           overwriting existing files
     --no-overwrite        Never overwrite existing files
     -r, -R, --recursive   Allow operation on directories as input
     -v                    Enables logging and sets detail level. Multiple -v
                           options increases verbosity (max: 4).
     -q, --quiet           Suppresses most warning and diagnostic messages

   For more usage instructions and examples, see: http://aws-encryption-sdk-cli.readthedocs.io/en/latest/


.. _AWS Encryption SDK: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html
.. _message header data: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-structure
.. _message header authentication data: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-authentication
.. _Read the Docs: http://aws-encryption-sdk-cli.readthedocs.io/en/latest/
.. _GitHub: https://github.com/awslabs/aws-encryption-sdk-cli/
.. _cryptography: https://cryptography.io/en/latest/
.. _cryptography installation guide: https://cryptography.io/en/latest/installation/
.. _data key caching documentation: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html
.. _encryption context: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
.. _KMSMasterKeyProvider: http://aws-encryption-sdk-python.readthedocs.io/en/latest/generated/aws_encryption_sdk.key_providers.kms.html#aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider
.. _argparse file support: https://docs.python.org/3/library/argparse.html#fromfile-prefix-chars
.. _named profile: http://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html
.. _setuptools entry point: http://setuptools.readthedocs.io/en/latest/setuptools.html#dynamic-discovery-of-services-and-plugins
.. _you must not specify a key: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/crypto-cli-how-to.html#crypto-cli-master-key
