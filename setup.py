from setuptools import setup

setup(
    packages=['gen_reverse'],
    entry_points={
        'console_scripts': ['gen-reverse=gen_reverse.command_line:main'],
    },
    install_requires=['PyYAML'],
)
