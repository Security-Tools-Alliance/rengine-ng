# Contributors Guide

## For who is this guide?

This guide is meant for users who want to contribute to the codebase of reNgine-ng, whether that is the application code or the JSON-file for adding packages. To keep all processes streamlined and consistent, we're asking you to stick to this guide whenever contributing.

Even though the guide is made for contributors, it's also strongly recommended that the UAD-ng team sticks to these guidelines. After all, we're a prime example.

## What are the guidelines?

### Branching strategy

As for our branching strategy, we're using [Release Branching](https://www.split.io/blog/the-basics-of-release-branching/).

In short, there's one trunk branch named `main` (also known as `master`). Apart from `main`/`master` there can be different short-lived branches, such as:

- Features (`feature/*`)
- Fixes (`hotfix/*` or simply `fix/*`)
- Dependency updates (`deps/*`)
- Etc.

Do mind that these branch names do only not apply to the addition of packages; for that, we use the following scheme: `[issue number][issue title]`. This can be done [automatically](https://docs.github.com/en/issues/tracking-your-work-with-issues/creating-a-branch-for-an-issue) too.

This is how it looks like and works:

![Trunk-Based Development](https://trunkbaseddevelopment.com/trunk1c.png)

### Commit messages

As for commits, we prefer using [Conventional Commit Messages](https://gist.github.com/qoomon/5dfcdf8eec66a051ecd85625518cfd13). When working in any of the branches listed above (if there's an existing issue for it), close it using a [closing keyword](https://docs.github.com/en/issues/tracking-your-work-with-issues/linking-a-pull-request-to-an-issue#linking-a-pull-request-to-an-issue-using-a-keyword). For more information regarding Conventional Commit Messages, see <https://www.conventionalcommits.org/en/v1.0.0/> as well.
