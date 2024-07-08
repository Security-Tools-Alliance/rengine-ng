# Contributors Guide

## For who is this guide?

This guide is meant for users who want to contribute to the codebase of reNgine-ng, whether that is the application code or the JSON-file for adding packages. To keep all processes streamlined and consistent, we're asking you to stick to this guide whenever contributing.

Even though the guide is made for contributors, it's also strongly recommended that the reNgine-ng team sticks to these guidelines. After all, we're a prime example.

## What are the guidelines?

### Branching strategy

As for our branching strategy, we're using [Release Branching](https://www.split.io/blog/the-basics-of-release-branching/).

In short, a release branch is created from the main branch when the team is ready to roll out a new version. Only necessary changes like bug fixes and final touch-ups are made. Once finalized, it merges with the main branch for deployment. Urgent fixes after the release are handled using hotfix branches, which merge back into both the release and main branches. We do not use a `develop` branch as that adds complexity.

Some examples of branches are:

- Features (`feature/*`)
- Fixes (`hotfix/*` or simply `fix/*`)
- Dependency updates (`deps/*`)
- Releases (`release/*`)

Do mind that these branch names do only not apply when there's already an issue for the pull request. In that case we use the following scheme: `[issue number][issue title]`. This can be done [automatically](https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-a-branch-for-an-issue) too.

This is how it looks like and works. The difference here is that we don't have a develop branch (so the purple dots that are connected with its mainline should not be included).

<img src="https://wac-cdn.atlassian.com/dam/jcr:cc0b526e-adb7-4d45-874e-9bcea9898b4a/04%20Hotfix%20branches.svg?cdnVersion=1871" alt="drawing" width="600"/>

So in short:

1. PR with feature/fix is opened
1. PR is merged into release branch
1. When we release a new version, release branch is merged to main

### Commit messages

As for commits, we prefer using [Conventional Commit Messages](https://gist.github.com/qoomon/5dfcdf8eec66a051ecd85625518cfd13). When working in any of the branches listed above (if there's an existing issue for it), close it using a [closing keyword](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue#linking-a-pull-request-to-an-issue-using-a-keyword). For more information regarding Conventional Commit Messages, see <https://www.conventionalcommits.org/en/v1.0.0/> as well.
