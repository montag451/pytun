from distutils.core import setup, Extension

setup(name='pytun',
      author='montag451',
      author_email='montag451 at laposte.net',
      maintainer='montag451',
      maintainer_email='montag451 at laposte.net',
      url='https://github.com/montag451/pytun',
      description='Linux TUN/TAP wrapper for Python',
      version='0.1',
      ext_modules=[Extension('pytun', ['pytun.c'])])

