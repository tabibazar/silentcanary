#!/usr/bin/env python3
"""
Test runner for SilentCanary
Runs unit tests and integration tests with coverage reporting
"""

import sys
import subprocess
import os
from pathlib import Path

def run_command(cmd, description):
    """Run a command and return success/failure"""
    print(f"\n🔄 {description}...")
    print(f"Running: {' '.join(cmd)}")
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        if result.stdout.strip():
            print("Output:", result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed")
        print("Error output:", e.stderr)
        if e.stdout:
            print("Standard output:", e.stdout)
        return False
    except Exception as e:
        print(f"❌ {description} failed with exception: {e}")
        return False

def install_test_dependencies():
    """Install test dependencies"""
    return run_command([
        sys.executable, "-m", "pip", "install", "-r", "requirements-test.txt"
    ], "Installing test dependencies")

def run_pytest(args=None):
    """Run pytest with coverage"""
    cmd = [
        sys.executable, "-m", "pytest",
        "--verbose",
        "--tb=short",
        "--cov=models",
        "--cov=app_dynamodb", 
        "--cov-report=term-missing",
        "--cov-report=html:htmlcov",
        "--cov-fail-under=70"
    ]
    
    if args:
        cmd.extend(args)
    else:
        cmd.append("tests/")
    
    return run_command(cmd, "Running tests with coverage")

def run_specific_test_file(test_file):
    """Run a specific test file"""
    return run_pytest([f"tests/{test_file}"])

def run_linting():
    """Run code linting (if flake8 is available)"""
    try:
        return run_command([
            sys.executable, "-m", "flake8", 
            "models.py", "app_dynamodb.py", "tests/",
            "--max-line-length=120",
            "--ignore=E501,W503"
        ], "Running linting checks")
    except:
        print("⚠️ Linting skipped (flake8 not available)")
        return True

def create_test_directories():
    """Create necessary test directories"""
    os.makedirs("tests", exist_ok=True)
    os.makedirs("htmlcov", exist_ok=True)
    
    # Create __init__.py in tests directory
    init_file = Path("tests/__init__.py")
    if not init_file.exists():
        init_file.touch()

def main():
    """Main test runner"""
    print("🧪 SilentCanary Test Suite")
    print("=" * 50)
    
    # Change to project directory
    project_dir = Path(__file__).parent
    os.chdir(project_dir)
    
    # Create test directories
    create_test_directories()
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] == "--install-deps":
            if not install_test_dependencies():
                sys.exit(1)
            return
        elif sys.argv[1] == "--lint":
            if not run_linting():
                sys.exit(1)
            return
        elif sys.argv[1].startswith("--file="):
            test_file = sys.argv[1].split("=", 1)[1]
            if not run_specific_test_file(test_file):
                sys.exit(1)
            return
        elif sys.argv[1] == "--help":
            print("\nUsage:")
            print("  python run_tests.py                 # Run all tests")
            print("  python run_tests.py --install-deps  # Install test dependencies")
            print("  python run_tests.py --lint          # Run linting")
            print("  python run_tests.py --file=<name>   # Run specific test file")
            print("  python run_tests.py --help          # Show this help")
            return
    
    success = True
    
    # Install dependencies
    if not install_test_dependencies():
        success = False
    
    # Run tests
    if success and not run_pytest():
        success = False
    
    # Run linting
    if success and not run_linting():
        success = False
    
    # Summary
    print("\n" + "=" * 50)
    if success:
        print("🎉 All tests passed!")
        print("\n📊 Coverage report generated in htmlcov/index.html")
        print("📋 Test results summary:")
        print("  ✅ Unit tests for models")
        print("  ✅ Integration tests for routes")
        print("  ✅ Authentication and authorization tests")
        print("  ✅ Code coverage analysis")
    else:
        print("❌ Some tests failed!")
        print("Please review the output above and fix any issues.")
        sys.exit(1)

if __name__ == "__main__":
    main()