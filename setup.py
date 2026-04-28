from setuptools import setup, find_packages

setup(
    name="recon",
    version="1.0.0",
    author="Arin",
    description="Network Reconnaissance Tool",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "colorama",
        "requests",
        "scapy",
        "fpdf2",
    ],
    entry_points={
        "console_scripts": [
            "recon=recon.main:cli",
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)
