# Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause

"""CLI application."""

import argparse
import csv
import json
import logging
from pathlib import Path
from typing import Any, Iterable

from sbom_check import CheckResult, check_sbom

logger = logging.getLogger(__name__)

SPDX_EXTENSION = ".spdx.json"
OUTPUT_FILENAME = "results.json"


def main() -> None:
    """
    Accepts arguments for running the validator through the CLI.
    """
    parser = argparse.ArgumentParser(description="sbom-check.")
    parser.add_argument(
        "spdx_folder",
        metavar="spdx_json_folder",
        help="Path to directory containing SPDX json file(s).",
    )
    parser.add_argument(
        "--print-console",
        action="store_true",
        help="Output results to console.",
    )
    parser.add_argument(
        "--print-json",
        action="store_true",
        help="Output results to a JSON file.",
    )
    args = parser.parse_args()

    results = run(args.spdx_folder)

    if args.print_console:
        _print_results(results)

    if args.print_json:
        _output_json(results)

    _output_csv(results)


def run(spdx_root: str) -> dict[str, CheckResult]:
    """
    Runs the validator using the cli provided arguments
    """
    results = {}
    for file, filename_error in _get_filenames(spdx_root):
        if filename_error:
            results[file.name] = CheckResult([], [filename_error])
            # skip further processing of non-SPDX file
            continue
        print(f"\nParsing {file}")
        with open(file, encoding="utf8") as content:
            json_string = content.read()
        results[file.name] = check_sbom(json_string)
    return results


def _get_filenames(path: str) -> Iterable[tuple[Path, str]]:
    directory = Path(path)
    for file in directory.glob("*"):
        if file.is_file() and file.name.lower().endswith(SPDX_EXTENSION):
            logger.info("SPDX file %s read.", file)
            yield file, ""
        else:
            error = (
                f"File {file} not recognized. Please ensure your files "
                f"are SPDX JSON format and end with '{SPDX_EXTENSION}'."
            )
            logger.warning(error)
            yield file, error


def _print_results(results: dict[str, CheckResult]) -> None:
    for filename, check_result in results.items():
        if not check_result.is_valid:
            print(f"\n{filename} is compliant.\n")
            continue

        if errors := check_result.errors:
            print(
                f"\n{filename} is not compliant, as it could not be parsed.\n"
                f"The following errors were found:\n"
            )
            for error in errors:
                print(f"* {error}\n")
            continue

        print(
            f"\n{filename} successfully parsed, but was not compliant with "
            "validation standards.\n"
            "The following validation issues were found:\n"
        )
        for message in check_result.validation_messages:
            _print_validation_message(message)


def _print_validation_message(message: dict[str, str]) -> None:
    print(f'* Message: {message["message"]}')
    print(f'\ttype: {message["element_type"]}')
    print(
        f'\tspdx_id: {message["spdx_id"] or None}, '
        f'parent id:{message["parent_id"]}\n'
    )


def _output_json(results: dict[str, CheckResult]) -> None:
    with open(OUTPUT_FILENAME, "w", encoding="utf-8") as file:
        json.dump(obj=_flattened_results(results), fp=file, indent=4)


def _flattened_results(results: dict[str, Any]) -> dict[str, Any]:
    return {
        filename: {
            "errors": result.errors,
            "validator_results": result.validation_messages,
        }
        for filename, result in results.items()
    }


def _output_csv(results: dict[str, CheckResult]) -> None:
    for filename, check_results in results.items():
        if not check_results.is_valid:
            with open(
                f"{filename}_exceptions.csv", "w", encoding="utf-8"
            ) as file:
                csvwriter = csv.writer(file)
                csvwriter.writerows(check_results.csv_rows)
