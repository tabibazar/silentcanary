# SilentCanary Testing Guide

## Overview
SilentCanary includes a comprehensive test suite with unit tests, integration tests, and security tests to ensure application reliability and prevent regressions.

## Test Structure

### Test Files
- `tests/test_models.py` - Unit tests for User, Canary, and CanaryLog models
- `tests/test_routes.py` - Integration tests for Flask routes and endpoints  
- `tests/test_auth.py` - Authentication and authorization security tests
- `conftest.py` - Test fixtures and configuration
- `pytest.ini` - Pytest configuration
- `requirements-test.txt` - Test dependencies

### Test Coverage
- **User Model**: Registration, authentication, password hashing, data retrieval
- **Canary Model**: Creation, check-ins, status tracking, ownership validation
- **CanaryLog Model**: Event logging, pagination, data retrieval
- **Routes**: All Flask endpoints with authentication and error handling
- **Security**: Access control, session management, CSRF protection

## Quick Start

### Install Test Dependencies
```bash
source venv/bin/activate
pip install -r requirements-test.txt
```

### Run All Tests
```bash
python run_tests.py
```

### Run Specific Test Categories
```bash
# Run only model tests
python -m pytest tests/test_models.py -v

# Run only route tests  
python -m pytest tests/test_routes.py -v

# Run only auth tests
python -m pytest tests/test_auth.py -v
```

### Run Tests with Coverage
```bash
python -m pytest --cov=models --cov=app_dynamodb --cov-report=html
```

## Test Features

### Mocked DynamoDB
Tests use `moto` library to mock AWS DynamoDB, providing:
- Isolated test environment
- No AWS charges during testing
- Consistent test data
- Fast test execution

### Test Fixtures
- `dynamodb_tables`: Creates mock DynamoDB tables for each test
- `test_user`: Pre-created test user with known credentials
- `test_canary`: Pre-created test canary linked to test user
- `authenticated_client`: Flask test client with logged-in user
- `test_log_entries`: Sample canary log entries for testing

### Security Testing
- Password hashing and validation
- Session management and cleanup
- Access control and authorization
- CSRF protection verification
- Data isolation between users

## Running Tests in CI/CD

### GitHub Actions Example
```yaml
- name: Install test dependencies
  run: pip install -r requirements-test.txt

- name: Run tests
  run: python run_tests.py

- name: Upload coverage
  uses: codecov/codecov-action@v3
  with:
    files: ./coverage.xml
```

### Test Environment Variables
The test suite automatically configures:
- `TESTING=True` - Enables Flask testing mode
- `WTF_CSRF_ENABLED=False` - Disables CSRF for testing
- `MAIL_SUPPRESS_SEND=True` - Prevents actual emails during tests
- `DYNAMODB_LOCAL=true` - Uses mocked DynamoDB

## Adding New Tests

### Model Tests
```python
def test_new_model_feature(self, dynamodb_tables):
    \"\"\"Test new model functionality\"\"\"
    # Arrange
    model = MyModel(param='value')
    
    # Act
    result = model.some_method()
    
    # Assert
    assert result == expected_value
```

### Route Tests
```python
def test_new_endpoint(self, authenticated_client):
    \"\"\"Test new API endpoint\"\"\"
    response = authenticated_client.get('/api/new-endpoint')
    assert response.status_code == 200
    
    data = response.get_json()
    assert data['status'] == 'success'
```

### Authentication Tests
```python
def test_access_control(self, client, dynamodb_tables):
    \"\"\"Test access control for new feature\"\"\"
    # Test without authentication
    response = client.get('/protected-route')
    assert response.status_code == 302  # Redirect to login
    
    # Test with authentication
    # ... login logic ...
    response = client.get('/protected-route')
    assert response.status_code == 200
```

## Test Maintenance

### Regular Tasks
1. **Run tests before commits**: Ensure no regressions
2. **Update test data**: Keep fixtures current with schema changes
3. **Review coverage**: Maintain >80% code coverage
4. **Security testing**: Add tests for new security features

### Troubleshooting

#### DynamoDB Connection Issues
```bash
# Clear any cached credentials
unset AWS_PROFILE AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

# Run specific test to isolate issue
python -m pytest tests/test_models.py::TestUser::test_user_creation -v
```

#### Import Errors
```bash
# Ensure you're in the project directory
cd /Users/reza/PycharmProjects/silentcanary-

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-test.txt
```

## Best Practices

### Test Writing
- **Arrange-Act-Assert**: Structure tests clearly
- **Independent tests**: Each test should be self-contained
- **Descriptive names**: Test names should explain what they test
- **Edge cases**: Test boundary conditions and error scenarios

### Test Data
- Use fixtures for consistent test data
- Clean up resources after tests
- Don't rely on external services
- Mock time-dependent functionality

### Coverage Goals
- **Unit tests**: >90% coverage for models
- **Integration tests**: All major user flows
- **Security tests**: All authentication and authorization paths
- **Error handling**: Test all error conditions

## Performance Testing

### Load Testing (Future Enhancement)
Consider adding performance tests for:
- Concurrent canary check-ins
- Large numbers of canaries per user
- Database query performance
- API response times

## Security Testing

### Current Security Tests
✅ Password hashing and validation
✅ Session management
✅ Access control and authorization
✅ Data isolation between users
✅ CSRF protection
✅ Input validation

### Future Security Enhancements
- SQL injection prevention (though using DynamoDB)
- XSS protection testing
- Rate limiting tests
- API authentication testing