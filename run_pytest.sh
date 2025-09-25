#!/bin/bash

# Activate virtual environment
source .venv/bin/activate

# Set environment variables
export DJANGO_SETTINGS_MODULE=me_website_project.settings_test
export PYTHONPATH=$PYTHONPATH:$(dirname "$0")

# Change directory to project root
cd "$(dirname "$0")"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Help message
show_help() {
    echo -e "${CYAN}Usage:${NC} ./run_pytest.sh [options] [test_path]"
    echo
    echo -e "${CYAN}Options:${NC}"
    echo -e "  ${YELLOW}-h, --help${NC}        Show this help message"
    echo -e "  ${YELLOW}-v, --verbose${NC}     Run tests with verbose output"
    echo -e "  ${YELLOW}-x, --exitfirst${NC}   Exit on first failure"
    echo -e "  ${YELLOW}-k PATTERN${NC}        Only run tests matching the pattern"
    echo -e "  ${YELLOW}--cov${NC}             Run with coverage report"
    echo -e "  ${YELLOW}--cov-html${NC}        Generate HTML coverage report"
    echo -e "  ${YELLOW}--tb=short${NC}        Short traceback output"
    echo -e "  ${YELLOW}--app=APP${NC}         Run tests for specific app (e.g., --app=accounts)"
    echo
    echo -e "${CYAN}Examples:${NC}"
    echo -e "  ${MAGENTA}./run_pytest.sh${NC}"
    echo -e "  ${MAGENTA}./run_pytest.sh --app=accounts${NC}"
    echo -e "  ${MAGENTA}./run_pytest.sh --cov --app=features${NC}"
    echo -e "  ${MAGENTA}./run_pytest.sh -k test_login${NC}"
    echo -e "  ${MAGENTA}./run_pytest.sh me_website_project/accounts/tests.py::LoginFormTests${NC}"
}

# Process arguments
PYTEST_ARGS="-v"
SPECIFIC_APP=""

while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -v|--verbose)
            PYTEST_ARGS="$PYTEST_ARGS -v"
            shift
            ;;
        -x|--exitfirst)
            PYTEST_ARGS="$PYTEST_ARGS -x"
            shift
            ;;
        -k)
            if [[ -z "$2" || "$2" == -* ]]; then
                echo -e "${RED}Error: -k requires a pattern${NC}"
                exit 1
            fi
            PYTEST_ARGS="$PYTEST_ARGS -k $2"
            shift 2
            ;;
        --cov)
            PYTEST_ARGS="$PYTEST_ARGS --cov=me_website_project"
            shift
            ;;
        --cov-html)
            PYTEST_ARGS="$PYTEST_ARGS --cov=me_website_project --cov-report=html"
            shift
            ;;
        --tb=*)
            PYTEST_ARGS="$PYTEST_ARGS $1"
            shift
            ;;
        --app=*)
            SPECIFIC_APP="${1#*=}"
            shift
            ;;
        *)
            # Assume it's a test path or other pytest argument
            PYTEST_ARGS="$PYTEST_ARGS $1"
            shift
            ;;
    esac
done

echo -e "${YELLOW}Running tests with pytest...${NC}"

# Run tests with pytest
if [ -n "$SPECIFIC_APP" ]; then
    echo -e "${BLUE}Running tests for app: $SPECIFIC_APP${NC}"
    python -m pytest $PYTEST_ARGS me_website_project/$SPECIFIC_APP/
else
    if [[ "$PYTEST_ARGS" == "-v" ]]; then
        # If no specific args were provided beyond default -v
        echo -e "${BLUE}Running all tests${NC}"
        python -m pytest -v me_website_project/
    else
        # Run with provided arguments
        echo -e "${BLUE}Running with arguments: $PYTEST_ARGS${NC}"
        python -m pytest $PYTEST_ARGS
    fi
fi

# Capture exit code
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
else
    echo -e "${RED}Tests failed with exit code $EXIT_CODE${NC}"
fi

exit $EXIT_CODE