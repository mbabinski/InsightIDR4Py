from setuptools import setup, find_packages

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="InsightIDR4Py",
    version="0.1",
    description="A Python client allowing simplified interaction with Rapid7's InsightIDR REST API.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    author="Micah Babinski",
    author_email="m.babinski.88@gmail.com",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    url="https://github.com/mbabinski/InsightIDR4Py",
    keywords="Rapid7, InsightIDR, SIEM, Logsearch, Investigations, Threats",
    install_requires=[
          "requests",
      ],

)
