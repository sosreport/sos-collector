from setuptools import setup, find_packages
from soscollector import __version__ as VERSION

setup(
    name='sos-collector',
    version=VERSION,
    description='Capture sosreports from clustered systems simultaneously',
    long_description=("sos-collector is a utility designed to capture "
                      "sosreports from multiple nodes at once and "
                      "collect them into a single archive. It is suited for "
                      "use by support engineers and administrators of "
                      "clustered or multi-node environments"),
    author='Jake Hunsaker',
    author_email='jhunsake@redhat.com',
    license='GPLv2',
    url='https://github.com/sosreport/sos-collector',
    classifiers=[
                'Intended Audience :: System Administrators',
                'Topic :: System :: Systems Administration',
                ('License :: OSI Approved :: GNU General Public License v2 '
                 "(GPLv2)"),
                ],
    packages=find_packages(),
    scripts=['sos-collector'],
    data_files=[
        ('share/man/man1/', ['man/en/sos-collector.1'])
    ])
