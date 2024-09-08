Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.  
SPDX-License-Identifier: BSD-3-Clause

# SBOM Check
Python library and CLI application that check a provided SPDX SBOM for
adherence to the official specification [SPDX 2.3 specification](https://spdx.github.io/spdx-spec/v2.3/)
and for the presence of a configurable set of required field values.

## Requirements
* Python 3.10+
* `pip`, `setuptools`
* See `requirements.txt` for Python application dependencies.

## CLI Application

### Setup
`virtualenv` usage is recommended.

Install Python dependencies:
```
 $ virtualenv ENV
 $ pip install -r requirements.txt
```

Install CLI application:
```
 $ python setup.py install
```

### Usage
The CLI application takes a single positional argument, the path to the root
of the SBOM directory in which the SPDX JSON files are located.

Run the `--help` command for full listing of CLI arguments.
```
 $ sbom-check --help
```

### Output
On completion, the application will output the status of the run along with a
detailed exceptions report if any validation checks failed.

## Contributions
Please see [CONTRIBUTIONS.md](CONTRIBUTIONS.md) for details.

## License
SPDX Validator is licensed under the BSD-3-Clause "New" or "Revised" License.
See [LICENSE](LICENSE) for the full license text.
