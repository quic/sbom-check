# Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

from sbom_check import check_sbom


def test_check_sbom():
    assert check_sbom("") is None
