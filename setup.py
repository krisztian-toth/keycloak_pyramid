import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="pyramid_keycloak",
    version="0.0.13",
    author="Krisztian Toth",
    author_email="tkrisztiana@gmail.com",
    description="Keycloak based authentication policy for Pyramid",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/watsta/keycloak_pyramid",
    packages=setuptools.find_packages(),
    install_requires=[
        'pyramid>1.0,<2.0',
        'python-keycloak<1.0'
    ],
    classifiers=(
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ),
)
