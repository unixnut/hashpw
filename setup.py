#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages


with open('README.md') as readme_file:
    readme = readme_file.read()
                
requirements = ['Click>=6.0',
                'py-bcrypt',
                'passlib']

setup(
    author="Alastair Irvine",
    description="Prompt for a password and prints the hash",
    install_requires=requirements,
    long_description=readme, ## + '\n\n' + history,
    long_description_content_type='text/markdown',
    entry_points={
        'console_scripts': [
            'hashpw=hashpw:main',
        ],
    },
    install_requires=requirements,
    keywords="password, hash, cli",
    name="hashpw",
    packages=find_packages(".", exclude=['tests']),
    url='https://github.com/unixnut/hashpw',
    version="2.2.0",
    zip_safe=False,
)



