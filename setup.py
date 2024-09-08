# Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

"""Installer for sbom-check library and CLI application."""

from setuptools import find_packages, setup

setup(
    name="sbom-check",
    author="Jesse Porter",
    author_email="quic_jporter@quicinc.com",
    url="https://github.com/quic/sbom-check",
    install_requires=["spdx-tools"],
    package_dir={"": "src"},
    packages=find_packages("src"),
    entry_points={"console_scripts": ["sbom-check = cli.main:main"]},
    setup_requires="setuptools_scm",
    use_scm_version=True,
)
