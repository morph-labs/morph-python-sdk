from setuptools import find_packages, setup
from setuptools.command.install import install


class PostInstallCommand(install):
    def run(self):
        install.run(self)


setup(
    name="morphcloud",
    version="0.1.9",
    use_scm_version=True,
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        "requests",
        "tqdm",
        "argparse",
        "shutil",
        "psutil",
        "streamlit",
        "anthropic",
        "openai",
        "pillow",
        "httpx",
        "fire",
        "playwright",
        "bs4",
        "click",
        "pytest",
        "pydantic",
        "httpx",
    ],
    entry_points={
        "console_scripts": [
            "morphcloud=morphcloud:main",
        ],
    },
    cmdclass={
        "install": PostInstallCommand,
    },
)
