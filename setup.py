from setuptools import setup

setup(
    entry_points={
        'console-scripts': ['gen-reverse=gen_reverse:command_line:main'],
    }
)
