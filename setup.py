import os
from setuptools import setup, find_packages

with open('requirements.txt') as f:
    required = f.read().splitlines()

setup(
    name='aplot',
    version='0.1.0',
    description='Atop log data analyzer.',
    packages=find_packages(),
    install_requires=required,
    entry_points={
        "console_scripts":
            [
                "aplot=aplot.__main__:main",
            ]
    },
    classifiers=[
        'Development Status :: 1 - Planning',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
    ],
)
