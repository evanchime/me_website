# Using pytest with Django Test Suite

This guide explains how to use pytest to run the Django test suite in the me_website project.

## Benefits of pytest

- Better test output formatting
- More powerful test filtering
- Better error reporting with traceback highlighting
- Built-in fixtures
- Support for parameterized testing
- Extensibility through plugins
- Coverage reports

## Prerequisites

The following packages should be installed in the virtual environment:
- pytest
- pytest-django
- pytest-cov

You can install them using:
```bash
pip install pytest pytest-django pytest-cov
```

## Running Tests with pytest

Use the provided `run_pytest.sh` script to run tests with pytest:

### Run all tests
```bash
./run_pytest.sh
```

### Run tests for a specific app
```bash
./run_pytest.sh --app=accounts
./run_pytest.sh --app=features
```

### Run a specific test file
```bash
./run_pytest.sh me_website_project/accounts/tests.py
```

### Run a specific test class
```bash
./run_pytest.sh me_website_project/accounts/tests.py::LoginFormTests
```

### Run a specific test method
```bash
./run_pytest.sh me_website_project/accounts/tests.py::LoginFormTests::test_valid_login_form
```

### Filter tests by name pattern
```bash
./run_pytest.sh -k "login or signup"
```

### Generate test coverage report
```bash
./run_pytest.sh --cov
```

### Generate HTML coverage report
```bash
./run_pytest.sh --cov-html
```
The HTML report will be created in the `htmlcov` directory.

### Stop on first failure
```bash
./run_pytest.sh -x
```

### Show help
```bash
./run_pytest.sh --help
```

## pytest.ini Configuration

The `pytest.ini` file contains configuration for pytest:

```ini
[pytest]
DJANGO_SETTINGS_MODULE = me_website_project.settings_test
python_files = tests.py test_*.py *_tests.py
filterwarnings =
    ignore::DeprecationWarning
    ignore::PendingDeprecationWarning
testpaths = me_website_project
pythonpath = .
```

## conftest.py Configuration

The `conftest.py` file at the project root helps pytest find the Django settings:

```python
import os
import sys
import django

# Add the project root directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'me_website_project')))

# Setup Django
def pytest_configure():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'me_website_project.settings_test')
    django.setup()
```

## Advanced Usage

### Running a subset of tests
```bash
# Run only test methods containing "login" in their name
./run_pytest.sh -k login

# Run tests in accounts and features apps
./run_pytest.sh me_website_project/accounts/ me_website_project/features/

# Run tests matching an expression
./run_pytest.sh -k "not test_login and test_signup"
```

### Running with verbose output
```bash
./run_pytest.sh -v
```

### Showing only the first failing test
```bash
./run_pytest.sh -x
```

### Showing only the first 5 failures
```bash
./run_pytest.sh --maxfail=5
```

### Shorter traceback output
```bash
./run_pytest.sh --tb=short
```

### Showing locals in tracebacks
```bash
./run_pytest.sh --showlocals
```
