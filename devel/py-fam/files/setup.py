from distutils.core import setup, Extension
import os
LOCALBASE = os.environ.get('LOCALBASE', '/usr/local')
setup(
    name="fam",
    ext_modules=[
        Extension(
            "_fam",
            ["_fam.c"],
            include_dirs=[f'{LOCALBASE}/include'],
            libraries=['fam'],
            library_dirs=[f'{LOCALBASE}/lib'],
        )
    ],
)
