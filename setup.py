#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""The setup script."""

from setuptools import setup, find_packages


with open('README.md') as readme_file:
    readme = readme_file.read()
                
requirements = ['bcrypt==4.0.1',  # See https://github.com/pyca/bcrypt/issues/684
                'passlib']

setup(
    description="Universal password hash generator and verifier",
    author="Alastair Irvine",
    author_email='alastair@plug.org.au',
    python_requires='>=3.5',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    install_requires=requirements,
    long_description=readme, ## + '\n\n' + history,
    long_description_content_type='text/markdown',
    entry_points={
        'console_scripts': [
            'hashpw=hashpw.cli:main',
        ],
    },
    keywords="password, hash, cli",
    name="hashpw",
    packages=find_packages('src'),
    package_dir={'': 'src'},
    url='https://github.com/unixnut/hashpw',
    version="2.6.0",
    zip_safe=False,
)



