#!/usr/bin/env python3
"""
Script to check the current version against PyPI and increment if needed.
"""
import re
import requests
import toml
from packaging import version

def increment_version():
    # Load current version from pyproject.toml
    pyproject = toml.load('pyproject.toml')
    current_version = pyproject['project']['version']
    
    # Get latest version from PyPI
    response = requests.get('https://pypi.org/pypi/morphcloud/json', timeout=2)
    latest_version = response.json()['info']['version']
    
    print(f'Current version: {current_version}')
    print(f'Latest version: {latest_version}')
    
    # Compare versions
    if version.parse(current_version) <= version.parse(latest_version):
        print('Incrementing version...')
        
        # Handle various version formats
        v = version.parse(latest_version)
        if hasattr(v, 'micro'):
            new_version = f'{v.major}.{v.minor}.{v.micro + 1}'
        else:
            parts = latest_version.split('.')
            parts[-1] = str(int(parts[-1]) + 1)
            new_version = '.'.join(parts)
            
        print(f'New version: {new_version}')
        
        # Update pyproject.toml
        with open('pyproject.toml', 'r') as f:
            content = f.read()
        
        with open('pyproject.toml', 'w') as f:
            f.write(re.sub(r'version = "(.*?)"', f'version = "{new_version}"', content))
            
    else:
        print('Current version is already newer than PyPI, keeping it.')

if __name__ == '__main__':
    increment_version()
