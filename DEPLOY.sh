#!/bin/bash

rm ./dist/*
python setup.py sdist
python -m twine upload --repository pypi dist/* 
