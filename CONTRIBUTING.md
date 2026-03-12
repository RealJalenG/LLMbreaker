# Contributing to LLMbreaker

First off, thank you for considering contributing to LLMbreaker! It's people like you that make the open-source community such a great place. We welcome any form of contribution, from reporting bugs and improving documentation to submitting new features and attack modules.

## Code of Conduct

This project and everyone participating in it is governed by the [LLMbreaker Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## How Can I Contribute?

### Reporting Bugs

- **Ensure the bug was not already reported** by searching on GitHub under [Issues](https://github.com/your-username/llmbreaker/issues).
- If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/your-username/llmbreaker/issues/new). Be sure to include a **title and clear description**, as much relevant information as possible, and a **code sample** or an **executable test case** demonstrating the expected behavior that is not occurring.

### Suggesting Enhancements

- Open a new issue to discuss your enhancement. Clearly describe the proposed enhancement and its potential benefits.
- We appreciate suggestions that align with the project's goal of being a proactive LLM red teaming framework.

### Pull Requests

1.  Fork the repo and create your branch from `main`.
2.  If you've added code that should be tested, add tests.
3.  If you've changed APIs, update the documentation.
4.  Ensure the test suite passes.
5.  Make sure your code lints.
6.  Issue that pull request!

## Styleguides

### Git Commit Messages

- Use the present tense ("Add feature" not "Added feature").
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...").
- Limit the first line to 72 characters or less.
- Reference issues and pull requests liberally after the first line.

### Python Styleguide

- We follow the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide.
- Use type hints for all function signatures.
- Write clear and concise comments where necessary.

## Adding a New Attack Module

One of the best ways to contribute is by adding a new attack module. Here's how:

1.  Create a new Python file in the `core/attacks/` directory (you may need to create this directory).
2.  Define a class that inherits from a base attack class (if available) or implements a standard interface.
3.  Implement the `generate` method, which should take a base prompt and other parameters and return a list of attack payloads.
4.  Add your new attack to the `ATTACK_METHODS` list in `config/settings.py`.
5.  Create a new YAML file in `config/attack_templates/` (you may need to create this directory) to define the templates for your new attack.
6.  Add a test case for your new attack module in the `tests/` directory.

We are excited to see your contributions!
