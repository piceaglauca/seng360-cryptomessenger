from setuptools import setup, find_packages


setup(
    name='crypto',
    packages=find_packages(),    
    install_requires=['cryptography==35.0.0', 'PyNaCl==1.4.0'],
)
