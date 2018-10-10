import setuptools

setuptools.setup(
    name="pyramid_keycloak",
    version="0.0.12",
    author="Krisztian Toth",
    author_email="tkrisztiana@gmail.com",
    description="Keycloak based authentication policy for Pyramid",
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
