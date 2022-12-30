from setuptools import setup, find_packages

setup(
    name='tlshelper',
    version='1.0.0',
    install_requires=[
        'pyOpenSsl==22.1.0',
        'wheel==0.38.4',
        'scapy==2.5.0',
        'click==8.1.3'
    ],
    packages=find_packages(
        include=["tlshelper", "tlshelper*"],
    ),
    entry_points={
        'console_scripts': [
            'tlshelper = tlshelper.tlshelper:main'
        ]
    }
)