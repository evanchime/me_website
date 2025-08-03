#!/bin/bash

# Test runner script for the me_website Django project
# This script sets up the environment and runs all tests

# Set the directory
PROJECT_DIR="/home/evan/me_website/me_website_project"

# Set environment variables for testing
export HEALTH_CHECK_SECRET="test-secret-for-tests"
export DJANGO_SETTINGS_MODULE="me_website_project.settings_test"

# Change to project directory
cd "$PROJECT_DIR"

echo "Running comprehensive test suite for me_website project..."
echo "============================================================="

# Function to run tests for a specific app
run_app_tests() {
    local app_name=$1
    echo ""
    echo "Testing $app_name app..."
    echo "------------------------"
    python3 manage.py test ${app_name}.tests -v 2
    if [ $? -ne 0 ]; then
        echo "❌ Tests failed for $app_name"
        return 1
    else
        echo "✅ Tests passed for $app_name"
    fi
}

# Function to run project-wide tests
run_project_tests() {
    local test_file=$1
    local test_name=$2
    echo ""
    echo "Testing $test_name..."
    echo "------------------------"
    python3 manage.py test $test_file -v 2
    if [ $? -ne 0 ]; then
        echo "❌ $test_name failed"
        return 1
    else
        echo "✅ $test_name passed"
    fi
}

# Test individual apps
APPS=("about" "accounts" "contact" "projects" "skills" "experience" "education" "features")

for app in "${APPS[@]}"; do
    run_app_tests $app
    if [ $? -ne 0 ]; then
        echo ""
        echo "❌ Test suite failed on $app app"
        exit 1
    fi
done

# Test project-wide functionality
run_project_tests "tests_integration" "Integration Tests"
if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Integration tests failed"
    exit 1
fi

run_project_tests "tests_health_check" "Health Check Tests"
if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Health check tests failed"
    exit 1
fi

run_project_tests "tests_forms" "Form Validation Tests"
if [ $? -ne 0 ]; then
    echo ""
    echo "❌ Form validation tests failed"
    exit 1
fi

echo ""
echo "============================================================="
echo "🎉 All tests passed successfully!"
echo ""
echo "Test Summary:"
echo "- Tested ${#APPS[@]} Django apps"
echo "- Tested integration functionality"
echo "- Tested health check endpoint"
echo "- Tested form validation and security"
echo ""
echo "Total test coverage includes:"
echo "  ✓ Unit tests for models, views, and forms"
echo "  ✓ Integration tests across apps"
echo "  ✓ Security tests (XSS, SQL injection, CSRF)"
echo "  ✓ Performance and load tests"
echo "  ✓ Error handling and edge cases"
echo "  ✓ Database integrity and transactions"
echo "  ✓ Template rendering and accessibility"
echo "  ✓ URL routing and configuration"
echo "  ✓ Authentication and authorization"
echo "  ✓ Cache headers and decorators"
echo ""
