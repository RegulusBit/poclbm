#!/usr/bin/env python

from detect import LINUX
from distribute_setup import use_setuptools
from setuptools import setup
from version import VERSION
use_setuptools()


try:
	import py2exe
except ImportError:
	py2exe = None


args = {
    'name': 'poclbm',
    'version': VERSION,
    'description': 'Genesis Bitcoin miner in python',
    'author': 'Cross',
    'author_email': 'cross@areatak.com',
    'url': 'https://github.com/areatak/gpuminer-genesis/',
    'install_requires': ['pyserial>=2.6'],
    'scripts': ['poclbm.py'],
}

if LINUX:
	args['install_requires'].append('pyudev>=0.16')

if py2exe:
	args.update({
		# py2exe options
		'options': {'py2exe':
						{'optimize': 2,
						'bundle_files': 2,
						'compressed': True,
						'dll_excludes': ['OpenCL.dll', 'w9xpopen.exe', 'boost_python-vc90-mt-1_39.dll'],
						'excludes': ["Tkconstants", "Tkinter", "tcl", "curses", "_ssl", "pyexpat", "unicodedata", "bz2"],
						},
					},
		'console': ['poclbm.py'],
		'data_files': ['phatk.cl'],
		'zipfile': None,
	})

setup(**args)
