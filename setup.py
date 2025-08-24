from setuptools import setup, find_packages

setup(
    name="wifi-strength-tester",
    version="1.0.0",
    packages=find_packages(),
    py_modules=["wifi_strength_tester"],
    install_requires=[
        "pywifi"
    ],
    entry_points={
        "console_scripts": [
            "phantom = wifi_strength_tester:main"
        ]
    },
)
