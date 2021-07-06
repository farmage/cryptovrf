import os
from distutils.core import setup, Extension

SRC_ROOT = os.path.relpath(os.path.dirname(__file__))

C_FILES = [
    'convert.c',
    'crypto_verify.c',
    'crypto_vrf.c',
    'ed25519_ref10.c',
    'keypair.c',
    'prove.c',
    'randombytes.c',
    'sha512EL.c',
    'verify.c',
    'vrf_interface.c']
    

C_DIR = os.path.join(SRC_ROOT,'src')

def get_extensions():

    libraries = []

    sources = [os.path.join(C_DIR, filename) for filename in C_FILES]

    extension = Extension(
        name="cryptovrf",
        sources=sources,
        include_dirs=[C_DIR],
        libraries=libraries,
        language="c",
        extra_compile_args=['-O2'])

    return [extension]

# [Extension("cryptovrf", ["src/convert.c","src/vrf_interface.c"])]




def main():
    setup(name="crypto_vrf",
          version="1.0.0",
          description="Python interface for VRF crypto function",
          author="farmage",
          author_email="farmage@protonmail.com",
          ext_modules=get_extensions())

if __name__ == "__main__":
    main()
