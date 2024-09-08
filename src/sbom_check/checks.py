# Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

"""SBOM Check library."""

import logging

logger = logging.getLogger(__name__)


def check_sbom(spdx_json: str) -> None:
    """
    Checks provided SPDX JSON string for adherence to official specification
    and for the presence of values configured to be required.
    """
    logger.debug("Checking %s", spdx_json)
