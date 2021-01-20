"""API compatibility tests for the AWS Encryption SDK CLI."""
import os
import re

from setuptools import find_packages, setup

VERSION_RE = re.compile(r"""__version__ = ['"]([0-9.]+)['"]""")
HERE = os.path.abspath(os.path.dirname(__file__))


def read(*args):
    """Read complete file contents."""
    return open(os.path.join(HERE, *args)).read()


def get_version():
    """Read the version from this module."""
    init = read("src", "awses_cli_api_compatibility_tests", "__init__.py")
    return VERSION_RE.search(init).group(1)

def get_requirements():
    """Read the requirements file."""
    requirements = read("requirements.txt")
    return list(requirements.strip().splitlines())


setup(
    name="aws-encryption-sdk-cli-api-compatibility-tests",
    version=get_version(),
    packages=find_packages("src"),
    package_dir={"": "src"},
    url="http://aws-encryption-sdk-cli.readthedocs.io/en/latest/",
    author="Amazon Web Services",
    author_email="aws-cryptools@amazon.com",
    maintainer="Amazon Web Services",
    description=(
        "API compatibility tests for the AWS Encryption SDK CLI."
    ),
    long_description=read("README.rst"),
    keywords="aws-encryption-sdk aws kms encryption cli command line",
    license="Apache License 2.0",
    install_requires=get_requirements(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ],
    entry_points={
        "console_scripts": ["aws-encryption-cli=aws_encryption_sdk_cli:cli"],  # noqa pylint: disable=line-too-long
    },
)