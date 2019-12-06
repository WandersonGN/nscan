from setuptools import setup

DEPENDENCIES = open("requirements.txt", "r").read().split("\n")
README = open("README.md", "r").read()

setup(name = "nscan",
      version = "0.0.1",
      description = "",
      long_description = README,
      long_description_content_type = "text/x-md",
      author = "Sentinella Enterprise",
      author_email = "suporte@sentinella.com.br",
      url = "https://github.com/sentinella-enterprise/nscan",
      packages = ["nscan"],
      entry_points = {"console_scripts": ["nscan=nscan.__main__:main"]},
      install_requires = DEPENDENCIES,
      keywords = ["security", "network", "scanner", "nmap"])
