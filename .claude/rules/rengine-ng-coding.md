---
description: Core coding standards for reNgine-ng (Python/Django, JS, PostgreSQL) and high-level project guidelines.
---

# reNgine-ng – Core coding standards

You are an expert in Python/Django/JS/PostgreSQL development and consistently deliver high-quality, non-duplicated code that follows KISS, DRY and SOLID principles.

## Project mantras

This project aims to follow these mantras:

- Do what is right
- Security by design
- Security by default
- Doing the right thing should be easy
- Batteries included – it just works
- No-nonsense bingo – no time to waste
- Better explicit than magical

## General expectations

- Follow existing patterns in the codebase before introducing new ones.
- Add type hints to all new code.
- Every code change must include appropriate tests.
- All code and comments must be written in English.
- Avoid comments that narrate refactors; only explain non-obvious intent.

## Architecture

Keep the project modular and layered to avoid circular dependencies:

- Leaf modules (like `logger.py`, `db.py`, or `utils.py`) sit at the bottom.
- Core business logic (services and repositories) sits in the middle.
- Orchestration layers (entrypoints, HTTP views, CLI files) sit at the top.

## Tooling

- Follow PEP8 and the Ruff configuration defined in `docker/web/pyproject.toml`.
- To check formatting and style:
  - Run `make ruff-format` to format.
  - Run `make ruff-fix` to apply autofixable lints.

## API usage

- API calls from the web interface cannot be replayed directly with `curl` because of CSRF protection.
- Use the User API key instead for automated tests; a dedicated test API key is available in the project.

## Cross-reference rules

- For Python/Django code quality and backend architecture, see `rengine-ng-python-backend.md`.
- For JavaScript, Datatables and UI conventions, see `rengine-ng-frontend.md`.
- For testing conventions (BaseTestCase, TestDataGenerator, anonymisation, determinism), see `rengine-ng-tests.md`.
- For Secator usage (workflows, scans, tasks, documentation), see `rengine-ng-secator.md` and the skill `rengine-ng-context`.

## Change management

- Do not perform radical changes without explicit discussion.
- Do not add new dependencies without maintainer approval.
- Do not modify the CI/CD configuration without understanding the entire pipeline.

