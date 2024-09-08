## Contributing to SBOM Check

Hi there!
We’re thrilled that you’d like to contribute to this project.
Your help is essential for keeping this project great and for making it better.

## Branching Strategy

In general, contributors should develop on branches based off of `main` and pull requests should be made against `main`.

## Submitting a pull request

1. Please read our [code of conduct](CODE-OF-CONDUCT.md) and [license](LICENSE).
1. [Fork](https://github.com/quic/sbom-check) and clone the repository.
 
    ```bash
    git clone https://github.com/<username>/sbom-check.git
    ```

1. Create a new branch based on `main`:

    ```bash
    git checkout -b <my-branch-name> main
    ```

1. Create an upstream `remote` to make it easier to keep your branches up-to-date:

    ```bash
    git remote add upstream https://github.com/quic/sbom-check.git
    ```

1. Make your changes, add tests, and make sure the tests, code quality, typing annotation, and style checks still pass.
  1. Run `tox -e autoformat` to run the `black` autoformatter and `isort` on the code.
  1. Run `tox` to run the CI checks locally.
  1. You can also run the various check individually via `tox`:
    1. `tox -e black` (code format)
    1. `tox -e isort` (imports format)
    1. `tox -e flake8` (code complexity/style)
    1. `tox -e mypy` (type annotation)
    1. `tox -e pylint` (code quality)
    1. `tox -e py310` (unit tests)

1. Commit your changes using the [DCO](http://developercertificate.org/). You can attest to the DCO by commiting with the **-s** or **--signoff** options or manually adding the "Signed-off-by":

    ```bash
    git commit -s -m "Really useful commit message"`
    ```

1. After committing your changes on the topic branch, sync it with the upstream branch:

    ```bash
    git pull --rebase upstream main
    ```

1. Push to your fork.

    ```bash
    git push -u origin <my-branch-name>
    ```

    The `-u` is shorthand for `--set-upstream`. This will set up the tracking reference so subsequent runs of `git push` or `git pull` can omit the remote and branch.

1. [Submit a pull request](https://github.com/quic/sbom-check/pulls) from your branch to `main`.
1. Pat yourself on the back and wait for your pull request to be reviewed.

Here are a few things you can do that will increase the likelihood of your pull request to be accepted:

- Follow the existing [style](https://peps.python.org/pep-0008/) where possible.
- Write tests.
- Keep your change as focused as possible.
  If you want to make multiple independent changes, please consider submitting them as separate pull requests.
- Write a [good commit message](http://tbaggery.com/2008/04/19/a-note-about-git-commit-messages.html).
- It's a good idea to arrange a discussion with other developers to ensure there is consensus on large features, architecture changes, and other core code changes. PR reviews will go much faster when there are no surprises.
