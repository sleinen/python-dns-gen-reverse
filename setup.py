from setuptools import setup

setup(
    entry_points={
        'console_scripts': ['gen-reverse=gen_reverse.command_line:main'],
    }
)
