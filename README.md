Copyright (c) 2024, Qualcomm Innovation Center, Inc. All rights reserved.  
SPDX-License-Identifier: BSD-3-Clause

# SBOM Check
Python library and CLI application that checks a provided SPDX v2.3
SBOM in JSON format for adherence to the official [specification](https://spdx.github.io/spdx-spec/v2.3/)
and for the presence of a set of minimum-required values.

## Requirements
* Python 3.10+
* `pip`, `setuptools`
* See `requirements.txt` for Python dependencies.

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
The CLI application takes a single positional argument, the path to the
root of the SBOM directory in which SPDX JSON files are located.
```
usage: sbom-check [-h] [--print-console] [--print-json] spdx_json_folder

sbom-check.

positional arguments:
  spdx_json_folder  Path to directory containing SPDX json file(s).

options:
  -h, --help        show this help message and exit
  --print-console   Output results to console.
  --print-json      Output results to a JSON file.
```

### Output
On completion, the application will output the status of the run along with
a detailed exceptions report if any validation checks failed.

## Contributions
Please see [CONTRIBUTIONS.md](CONTRIBUTIONS.md) for details.

## License
SPDX Validator is licensed under the BSD-3-Clause "New" or "Revised" License.
See [LICENSE](LICENSE) for the full license text.
