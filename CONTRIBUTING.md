# Contributors Guide

Contributions are what make the open-source community such an amazing place to learn, inspire and create. Every contributions you make is **greatly appreciated**. Your contributions can be as simple as fixing the indentation or UI, or as complex as adding new modules and features.

You can also [join our Discord channel](https://discord.gg/KE5QGTqJpS) for any development-related questions.
Channel is restricted, so please ask an admin to give you the correct role.

## For who is this guide?

This guide is meant for users who want to contribute to the codebase of reNgine-ng, whether that is the application code or the JSON-file for adding packages. To keep all processes streamlined and consistent, we're asking you to stick to this guide whenever contributing.

Even though the guide is made for contributors, it's also strongly recommended that the reNgine-ng team sticks to these guidelines. After all, we're a prime example.

## What are the guidelines?

### Submitting issues

You can submit issues related to this project, but you should do it in a way that helps developers to resolve it as quickly as possible.

For that, you need to add as much valuable information as possible.

You can have this valuable information by following these steps:

* Go to the root of the git cloned project
* Shutdown your current production instance by typing `make down`
* Launch the dev environment by typing `make dev_up`
* Then you can start `make logs` and run into your issue, you should now have a more detailed log (stack trace ...)
* To deactivate the dev environment, run `make dev_down`, then restart the prod with `make up`

Example with the tool arsenal version check API bug.

```bash
web_1          |   File "/usr/local/lib/python3.10/dist-packages/celery/app/task.py", line 411, in __call__
web_1          |     return self.run(*args, **kwargs)
web_1          | TypeError: run_command() got an unexpected keyword argument 'echo'
```

Now you know the real error is `TypeError: run_command() got an unexpected keyword argument 'echo'`, and you can post the full stack trace to your newly created issue to help developers to track the root cause of the bug and correct the bug easily.

**Activating debug like this also give you the Django Debug Toolbar on the left side & full stack trace in the browser** instead of an error 500 without any details.
So don't forget to open the developer console and check for any XHR request with error 500.
If there's any, check the response of this request to get your detailed error.

<img src="https://user-images.githubusercontent.com/1230954/276260955-ed1e1168-7c8f-43a3-b54d-b6285d52b771.png">

Happy issuing ;)

### Support

We are volunteers, working hard on reNgine-ng to add new features with the sole aim of making it the de facto standard for reconnaissance. Help is welcome, you can help us out by opening a PR.
Come to [the Discord](https://discord.gg/KE5QGTqJpS) to discuss with the reNgine-ng team.

* Add a [GitHub Star](https://github.com/Security-Tools-Alliance/rengine-ng) to the project.
* Tweet about this project, or maybe blogs?
* Maybe nominate us for [GitHub Stars?](https://stars.github.com/nominate/)

Any support is greatly appreciated! Thank you!

### First-time Open Source contributors

Please note that reNgine-ng is beginner friendly. If you have never done open-source before, we encourage you to do so. **We will be happy and proud of your first PR ever.**

You can start by resolving any [open issues](https://github.com/Security-Tools-Alliance/rengine-ng/issues).

### Branching strategy

As for our branching strategy, we're using [Release Branching](https://www.split.io/blog/the-basics-of-release-branching/).

In short, a release branch is created from the main branch when the team is ready to roll out a new version. Only necessary changes like bug fixes and final touch-ups are made. Once finalized, it merges with the main branch for deployment. Urgent fixes after the release are handled using hotfix branches, which merge back into both the release and main branches. We do not use a `develop` branch as that adds complexity.

Some examples of branches are:

* Features (`feature/*`)
* Fixes (`hotfix/*` or simply `fix/*`)
* Dependency updates (`deps/*`)
* Releases (`release/*`)

Do mind that these branch names do only not apply when there's already an issue for the pull request. In that case we use the following scheme: `[issue number][issue title]`. This can be done [automatically](https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-a-branch-for-an-issue) too.

This is how it looks like and works. The difference here is that we don't have a develop branch (so the purple dots that are connected with its mainline should not be included).

<img src="https://wac-cdn.atlassian.com/dam/jcr:cc0b526e-adb7-4d45-874e-9bcea9898b4a/04%20Hotfix%20branches.svg?cdnVersion=1871" alt="drawing" width="600"/>

So in short:

1. PR with feature/fix is opened
1. PR is merged into release branch
1. When we release a new version, release branch is merged to main

### Commit messages

As for commits, we prefer using [Conventional Commit Messages](https://gist.github.com/qoomon/5dfcdf8eec66a051ecd85625518cfd13). When working in any of the branches listed above (if there's an existing issue for it), close it using a [closing keyword](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue#linking-a-pull-request-to-an-issue-using-a-keyword). For more information regarding Conventional Commit Messages, see <https://www.conventionalcommits.org/en/v1.0.0/> as well.

## Coding Standards

Always follow **PEP8** style for Python code.  
Use **Ruff** and **pre-commit** to automate code checking and formatting before each commit.

## Code Checking and Formatting

### Using Docker

If Docker and your IDE are on the same host, you can directly apply the project's configuration before committing.

```bash
# Format code according to the project's Ruff configuration
docker exec -it rengine-web-1 bash -c 'poetry run ruff format --config /home/rengine/pyproject.toml $FilePath$'

# Check and automatically fix issues
docker exec -it rengine-web-1 bash -c 'poetry run ruff check --fix --config /home/rengine/pyproject.toml $FilePath$'
```

This ensures consistency between your development environment and the containerized project.

### Using Global Environment

If Docker is not available, or you prefer to work in a global Python environment, you can install Ruff and pre-commit using **pipx**:

```bash
pipx install ruff
pipx install pre-commit
```

After installation, set up pre-commit to run automatically before each commit:

```bash
pre-commit install --config docker/web/pre-commit-config.yaml
```

With this setup, all Python files will be automatically checked and formatted according to the project rules before each commit.  

This alternative method is convenient for contributors who do not run the full Docker stack locally.