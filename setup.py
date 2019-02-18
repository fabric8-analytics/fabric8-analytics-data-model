#!/usr/bin/env python3

# Copyright © 2019 Red Hat Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Author: Yusuf Zainee <yzainee@redhat.com>
#

"""Project setup file for fabric8 analytics notifications project."""

from setuptools import setup, find_packages


def get_requirements():
    """Parse all packages mentioned in the 'requirements.txt' file."""
    with open('requirements.txt') as fd:
        lines = fd.read().splitlines()
        reqs, dep_links = [], []
        for line in lines:
            if line.startswith('git+'):
                dep_links.append(line)
            else:
                reqs.append(line)
        return reqs, dep_links


# pip doesn't install from dependency links by default,
# so one should install dependencies by
#  `pip install -r requirements.txt`, not by `pip install .`
#  See https://github.com/pypa/pip/issues/2023
reqs, dep_links = get_requirements()
setup(
    name='fabric8-analytics-data-model',
    version='0.1',
    scripts=[
    ],
    packages=find_packages(exclude=['tests', 'tests.*']),
    install_requires=reqs,
    dependency_links=dep_links,
    include_package_data=True,
    author='Yusuf Zainee',
    author_email='yzainee@redhat.com',
    description='data importer for fabric8 analytics',
    license='ASL 2.0',
    keywords='fabric8-analytics-data-model',
    url=('https://github.com/fabric8-analytics/'
         'fabric8-analytics-data-model')
)