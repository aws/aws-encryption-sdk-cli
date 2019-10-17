######################
aws-encryption-sdk-cli
######################

.. image:: https://img.shields.io/pypi/v/aws-encryption-sdk-cli.svg
   :target: https://pypi.python.org/pypi/aws-encryption-sdk-cli
   :alt: Latest Version

.. image:: https://img.shields.io/pypi/pyversions/aws-encryption-sdk-cli.svg
   :target: https://pypi.python.org/pypi/aws-encryption-sdk-cli
   :alt: Supported Python Versions

.. image:: https://img.shields.io/badge/code_style-black-000000.svg
   :target: https://github.com/ambv/black
   :alt: Code style: black

.. image:: https://readthedocs.org/projects/aws-encryption-sdk-cli/badge/
   :target: https://aws-encryption-sdk-cli.readthedocs.io/en/stable/
   :alt: Documentation Status

.. image:: https://travis-ci.org/aws/aws-encryption-sdk-cli.svg?branch=master
   :target: https://travis-ci.org/aws/aws-encryption-sdk-cli

.. image:: https://ci.appveyor.com/api/projects/status/jp8kywq86ctxgn3b/branch/master?svg=true
   :target: https://ci.appveyor.com/project/mattsb42-aws/aws-encryption-sdk-cli-oruqs

You can use this command line version of the `AWS Encryption SDK`_ to encrypt and decrypt
the data in your files and directories.

The latest full documentation is at `Read the Docs`_ and you can find additional details
 and examples in `AWS Encryption CLI topic`_ of the `AWS Encryption SDK Developer Guide`_.

Find us on `GitHub`_.

***************
Getting Started
***************

Prerequisites
=============

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

The `encryption context`_ is an optional, but recommended, set of key-value pairs that
contain arbitrary nonsecret data. The encryption context can contain any data you choose, 
but it typically consists of data that is useful in logging and tracking, such as data 
about the file type, purpose, or ownership.

The encryption context is cryptographically bound to the encrypted data and is included in 
plain text in the encrypted message. 

The ``aws-encryption-cli`` also includes the encryption context in the metadata for the
operation. For more information, see `Output Metadata`_.

.. code-block:: sh

   --encryption-context key1=value1 key2=value2 "key 3=value with spaces"

Decrypt
```````

If you provide an encryption context in a decrypt command, the ``aws-encryption-cli`` 
verifies that the message being decrypted was encrypted with an encryption context that 
meets the following requirements.

If you provide ``key=value`` pairs, the encryption context in the encrypted message must 
contain matching pairs.

.. code-block:: sh

   --encryption-context required_key=required_value classification=secret

If you provide only ``key`` elements, the encryption context in the encrypted message 
must contain those keys, regardless of the values. You can mix ``key`` and ``key=value`` 
elements in the same parameter value.

.. code-block:: sh

   --encryption-context required_key classification=secret

If the encryption context check fails, the output metadata includes additional 
information about the failure. For more information, , see 
`Encryption Context Failures`_.
   
.. warning::

   The ``aws-encryption-cli`` deletes any existing output files before checking 
   the encryption context. If the encrypted message does not satisfy the encryption 
   context requirements, the decrypt operation stops, but the deleted output file 
   is not restored.


Output Metadata
---------------
In addition to the primary output of the operation, the ``aws-encryption-cli`` generates
useful metadata about the encrypt and decrypt operation. This metadata includes 
information about the operation as well as the complete header of the encrypted message.

The ``aws-encryption-cli`` writes the metadata to a text file that you specify. The 
metadata consists of a single line of formatted JSON for each cryptographic operation. 
When a command performs multiple operations, the ``aws-encryption-cli`` writes a separate 
line of JSON for each operation.

The metadata file contains lines of JSON, but it is not formatted as a JSON file.

 There are three options for writing metadata:

* ``--metadata-output FILE`` : Writes the metadata output to ``FILE`` (can be ``-`` for 
  stdout as long as primary output is not stdout). By default, the ``aws-encryption-cli`` 
  appends the metadata entry to the end of ``FILE``.
* ``--overwrite-metadata`` : Force the ``aws-encryption-cli`` to overwrite the contents 
  of ``FILE`` with the new metadata.
* ``-S/--suppress-metadata`` : Suppresses the metadata.

Metadata Contents
`````````````````
The metadata JSON contains the following fields:

* ``"mode"`` : ``"encrypt"``/``"decrypt"``
* ``"input"`` : Full path to input file (or ``"<stdin>"`` if stdin)
* ``"output"`` : Full path to output file (or ``"<stdout>"`` if stdout)
* ``"header"`` : JSON representation of `message header data`_
* ``"header_auth"`` : JSON representation of `message header authentication data`_ (only on decrypt)

Encryption Context Failures
~~~~~~~~~~~~~~~~~~~~~~~~~~~
When a decrypt operation fails because the encryption context that was specified in 
the decrypt operation does not match any elements in the encryption context of the 
encrypted message, the ``aws-encryption-cli`` writes the following additional fields 
in the metadata:

* ``skipped`` : ``true``
* ``reason`` : ``"Missing encryption context key or value"``
* ``missing_encryption_context_keys`` : List of encryption context keys that were 
  specified in the decrypt operation, but were missing from the message.
* ``missing_encryption_context_pairs`` : List of encryption context key-value pairs 
  that were specified in the decrypt operation, but were missing from the message.


Master Key Provider
-------------------
You must provide information about your master key provider.

Parameters may be provided using `Parameter Values`_.
The parameter values are formatted as ``key=value`` pairs.

Required parameters:

* **provider** *(default: aws-encryption-sdk-cli::aws-kms)* : Identifies the master 
  key provider.

    * For more information about using custom master key providers, see 
      `Advanced Configuration`_.

* **key** *(at least one required, many allowed)* : Identifies the master key. Any 
  identifer that the master key provider recognizes is valid.

    * If you are using ``aws-kms`` to decrypt, `you cannot specify a key`_.

The ``aws-encryption-cli`` collects any additional parameters into lists by parameter 
name and passes them to the master key provider entry point when it is instantiated. 
Custom master key providers must accept all arguments as prepared. See 
`Advanced Configuration`_ for more information.

To specify multiple master keys, you can use multiple instances of the ``key`` argument 
or define multiple ``--master-keys`` groups.

If you specify multiple master key providers, the first master key provider is treated
as the primary.

If you specify multiple master keys for the primary master key provider, the first 
master key is treated as the primary. The primary master key is used to generate the 
data key.

The ``aws-encryption-cli`` uses the following logic to construct all master key 
providers. This example uses ``KMSMasterKeyProvider``.

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
To use the ``aws-kms`` master key provider, you can either specify ``aws-kms`` in the 
provider attribute or omit the provider attribute.

You can use the following parameter attributes only with the ``aws-kms`` master key 
provider:

* **region**  : Use the specified the target region.
* **profile** : Use the credentials and region in the specified `named profile`_.

The following logic determines which AWS Region to use:

.. code-block:: python

   if key ID is an ARN:
      use the AWS Region in the ARN
   else:
      if an AWS Region is specified:
         use it
      else if profile is specified and profile includes an AWS Region:
         use AWS Region in the profile
      else:
         use system default AWS Region

Advanced Configuration
``````````````````````
To use a different master key provider, that provider must register a
`setuptools entry point`_. You can find an example of registering this entry point 
in the ``setup.py`` for this package.

When you specify a provider name, the ``aws-encryption-cli`` uses the entry point 
for that name.

Handling Multiple Entry Points
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
If multiple entry points are registered for a given name, you need to 
specify the package that registered the entry point you want to use.

To specify the package name, use the format: ``PACKAGE_NAME::ENTRY_POINT``.


* ``provider=aws-kms``
* ``provider=aws-encryption-sdk-cli::aws-kms``

If you supply a package and an entry point name, the ``aws-encryption-cli`` uses that 
entry point. If the entry point is not accessible, the ``aws-encryption-cli`` raises an 
error.

If you supply only an entry point name and there is only one entry point registered for 
that name, the ``aws-encryption-cli`` uses that entry point.

If you supply only an entry point name, but there is more than one entry point registered
for that name, the ``aws-encryption-cli`` raises an error that includes a list all 
packages that have an entry point registered for that name.

External Master Key Providers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
The entry point name cannot contain the string ``::``. This is used as a namespace
separator, as descibed in `Handling Multiple Entry Points`_.

When called, these entry points must return an instance of a master key provider. They 
must accept the parameters prepared by the CLI, as described in `Master Key Provider`_.

These entry points must be registered in the 
``aws_encryption_sdk_cli.master_key_providers`` group.

If the entry point raises a ``aws_encryption_sdk_cli.exceptions.BadUserArgumentError``, 
the CLI displays the error message to the user to indicate invalid user input.

Data Key Caching
----------------
Data key caching is optional, but if you use it, you must provide values for the required 
parameters. For detailed information about using data key caching with the AWS Encryption 
SDK, see the `data key caching documentation`_.

You can find an example of using data key caching in the ``aws-encryption-cli`` 
in `AWS Encryption CLI Examples`_. 

The `data key caching`_ parameter arguments have a ``key=value`` format.

Parameters may be provided using `Parameter Values`_.

Data key caching parameters:

* **capacity** *(required)* : Number of entries that the cache will hold.
* **max_age** *(required)* :  Determines how long each entry can be used, beginning when
  it was added to the cache.
* **max_messages_encrypted** :  Specifies the maximum number of messages that a cached data 
  key can encrypt. The default value is 2^32.
* **max_bytes_encrypted** : Specifies the maximum number of bytes that a cached data key can 
  encrypt. The default value is 2^63 - 1.


Logging and Verbosity
---------------------
The ``-v`` argument allows you to tune the verbosity of the built-in logging feature to your
desired level. The more ``-v`` arguments you supply, the more verbose the output becomes.

* unset : ``aws-encryption-cli`` logs all warnings, all dependencies log only critical messages
* ``-v`` :  ``aws-encryption-cli`` performs moderate logging, all dependencies log only
  critical messages
* ``-vv`` :  ``aws-encryption-cli`` performs detailed logging, all dependencies log only
  critical messages
* ``-vvv`` :  ``aws-encryption-cli`` performs detailed logging, all dependencies 
  perform moderate logging
* ``-vvvv`` :  ``aws-encryption-cli`` performs detailed logging, all dependencies perform 
  detailed logging

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
You can save ``aws-encryption-cli`` parameters and values in configuration files. 
When you refer to the configuration file in a command, the parameters and values 
in the file are added to the command, just as if you had typed them. This feature 
lets you standardize and reuse parameter values, and prevents typing errors.

.. warning::

   There is a `known issue with configuration file parsing in Windows`_. On Windows 
   only, configuration files cannot contain quotation marks (single or double). 
   ``aws-encryption-cli`` commands fail if they refer to configuration files that 
   contain quotation marks. If this affects you, please let us know by filing an issue 
   in our `GitHub`_ repo. 
   
   
Configuration files are supported by using Python's native `argparse file support`_, 
which allows you to write configuration files exactly as you would enter arguments in 
the shell. 

Configuration files are text files. They can have any valid file name and extension. 

To refer to a configuration file in an ``aws-encryption-cli`` command, prefix the file 
name with ``@``. 

.. note::

   In PowerShell, use a backtick to escape the ``@`` symbol (```@``) so that the 
   configuration file reference is sent to ``aws-encryption-cli`` and not interpreted 
   by PowerShell.

For example, to use a common master key configuration for multiple commands, create 
a ``master-key.conf`` file that contains the parameters and parameter values that 
describe your master key configuration.

**master-key.conf**

.. code-block:: sh

   --master-key key=A_KEY key=ANOTHER_KEY

In the ``aws-encryption-cli`` command, enter the remaining parameters and reference 
the configuration file. The ``aws-encryption-cli`` combines the parameters on the 
command line with the parameters in the configuration file.

.. code-block:: sh

   aws-encryption-cli -e -i $INPUT_FILE -o $OUTPUT_FILE --metadata-output $METADATA_FILE @master-key.conf

   To create a configuration file that saves your data key caching settings, save
   the caching parameter and its attributes in a configuration file. The following 
   example creates a ``caching.conf`` configuration file and uses it in two different 
   commands.

**caching.conf**

.. code-block:: sh

   --caching capacity=10 max_age=60.0 max_messages_encrypted=15

.. code-block:: sh

   aws-encryption-cli -e -i $INPUT_FILE -o $OUTPUT_FILE @master-key.conf @caching.conf

You can place the configuration file reference in any position in an ``aws-encryption-cli``
command. 

.. code-block:: sh

   aws-encryption-cli -e -i $INPUT_DIR -o $OUTPUT_DIR @master-key.conf @caching.conf --recursive

Configuration files can have many lines, include comments using ``#``. Escape characters are
platform-specific: ``\`` on Linux and MacOS and ````` on Windows. Configuration files may
also include references to other configuration files.

**my-encrypt.config**

.. code-block:: sh

   --encrypt
   @master-key.conf # Use existing master key config
   @caching.conf
   # Always recurse, but prompt before overwriting.
   --recursive
   --interactive

.. code-block:: sh

   aws-encryption-cli @my-encrypt.config -i $INPUT -o $OUTPUT


Encoding
--------
By default, ``aws-encryption-cli`` always returns raw binary data and expects
raw binary data as input. However, there are some cases where binary data is 
undesirable.

You might want to avoid binary data as a convenience:

* Accepting ciphertext from a person through stdin.
* Displaying ciphertext to a person in stdout.

Sometimes, you cannot accept binary data.

* Saving ciphertext output to a shell variable.

   * Most shells encode any data stored in a variable. Data might be corrupted if 
     it is stored  in a variable without encoding.

* Piping ciphertext in PowerShell.

   * All data passed through a PowerShell pipe is encoded using the
     system encoding.

To address these scenarios, ``aws-encryption-cli`` includes a built-in encoding and decoding feature. We provide two optional parameters:

* ``--decode`` : Base64-decode input before processing.
* ``--encode`` : Base64-encode output after processing.

These can be used independently or together, on any valid input or output.

Be aware, however, that if you target multiple files either through a path expansion or by
targetting a directory, decoding/encoding applies to all files.


Execution
=========

.. The contents of the following code block was copied from autogenerated output. 
   To change it, edit `arg_parsing.py`_

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
                           Output file for metadata records
     --overwrite-metadata  Force metadata output to overwrite file contents, 
                           rather than appending to file
     -m MASTER_KEYS [MASTER_KEYS ...], --master-keys MASTER_KEYS [MASTER_KEYS ...]
                           Identifies a master key provider and
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

   For more usage instructions and examples, see: http://aws-encryption-sdk-cli.readthedocs.io/en/latest/ and https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/crypto-cli-examples.html.

  
   
.. _AWS Encryption SDK: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html
.. _AWS Encryption SDK Developer Guide: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/introduction.html
.. _AWS Encryption CLI topic: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/crypto-cli.html
.. _AWS Encryption CLI Examples: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/crypto-cli-examples.html
.. _message header data: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-structure
.. _message header authentication data: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/message-format.html#header-authentication
.. _Read the Docs: http://aws-encryption-sdk-cli.readthedocs.io/en/latest/
.. _GitHub: https://github.com/aws/aws-encryption-sdk-cli/
.. _cryptography: https://cryptography.io/en/latest/
.. _cryptography installation guide: https://cryptography.io/en/latest/installation/
.. _data key caching documentation: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/data-key-caching.html
.. _encryption context: http://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context
.. _KMSMasterKeyProvider: http://aws-encryption-sdk-python.readthedocs.io/en/latest/generated/aws_encryption_sdk.key_providers.kms.html#aws_encryption_sdk.key_providers.kms.KMSMasterKeyProvider
.. _argparse file support: https://docs.python.org/3/library/argparse.html#fromfile-prefix-chars
.. _named profile: http://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html
.. _setuptools entry point: http://setuptools.readthedocs.io/en/latest/setuptools.html#dynamic-discovery-of-services-and-plugins
.. _you must not specify a key: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/crypto-cli-how-to.html#crypto-cli-master-key
.. _known issue with configuration file parsing in Windows: https://github.com/awslabs/aws-encryption-sdk-cli/issues/110
.. _arg_parsing.py: https://github.com/awslabs/aws-encryption-sdk-cli/blob/master/src/aws_encryption_sdk_cli/internal/arg_parsing.py
