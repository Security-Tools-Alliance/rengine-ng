# reNgine-ng Skills Documentation

## Overview
reNgine-ng is a web-based vulnerability scanner and security assessment platform. This document outlines the technologies, frameworks, and tools used in the application.

## Core Technologies

### Backend Framework
- **Django** (4.x+)
  - Web framework for building the application
  - Django ORM for database operations
  - Django REST Framework for API endpoints
  - Authentication and permission system

### Programming Language
- **Python** (3.8+)
  - Primary language for backend logic
  - Asynchronous operations and background tasks

### Task Queue & Background Processing
- **Secator** (0.25.1+)
  - Manages asynchronous task execution for scanning operations
  - Handles scan lifecycle and workflow orchestration
  - Integrates with Redis for task management
  - Celery tasks delegated to Secator runner

### Database
- **PostgreSQL** (12+)
  - Primary database for persistent storage
  - User data, targets, scans, results, and configuration
- **PgBouncer**
  - Connection pooling for PostgreSQL
  - Improves database performance and scalability

### Frontend
- **HTML5** - Structure and layout
- **CSS3** - Styling (Bootstrap-based)
- **JavaScript (ES6+)**
  - Frontend interactivity
  - AJAX requests for API calls
  - Real-time updates and notifications

## Security & Scanning

### Core Security Scanner
- **secator**
  - Python security scanning library
  - Orchestrates scanning tasks and workflows
  - Integrates multiple security tools
  - Handles scan lifecycle management

### Scanner Integration
- Multiple security scanning tools
  - Subdomain enumeration
  - Port scanning
  - Vulnerability assessment
  - Web application testing
  - Network reconnaissance

## Deployment & Infrastructure

### Containerization
- **Docker**
  - Application containerization
  - Container orchestration with Docker Compose
  - Multi-container applications

### Application Server
- **Uvicorn** (0.35.0+)
  - Production ASGI HTTP server
  - Runs reNgine.asgi:application
  - Configured with 4 workers, WebSockets support
- **Daphne** (4.1.2+)
  - Development ASGI server
  - Used in development with auto-reload
  - Supports WebSockets and HTTP/2

### Reverse Proxy
- **Nginx**
  - HTTP server and reverse proxy
  - Load balancing
  - SSL/TLS termination
  - Static file serving

## API & Integration

### REST API
- **Django REST Framework**
  - RESTful API endpoints
  - Authentication and authorization
  - Request/response handling

### External API Integration
- **API Key Authentication**
  - Secure API key management
  - API key-based authentication for external services

## Monitoring & Logging

### Logging
- **Python logging module**
  - Structured logging for scan operations
  - Error tracking and debugging

### Health Checks
- **API health check endpoints**
  - Container health monitoring
  - Service availability checks

## Key Features & Modules

### User Management
- Django authentication system
- User profiles and permissions
- Role-based access control
- Session management

### Target Management
- Target creation and management
- Target categorization and organization
- Target aggregation and queries
- Scope management with per-target overrides

### Scan Management
- Scan workflow orchestration
- Multiple scan execution modes:
  - Workflow-based scans
  - Task-based scans
  - Scan type-based scans
- Sub-scan support
- Scan history and results tracking

### Worker Management
- Remote worker deployment
- SSH-based worker execution
- Worker health monitoring
- Worker configuration and management

### Dashboard & UI
- Responsive web interface
- Real-time updates
- Data tables with sorting/filtering
- Custom visualizations and charts

## Development Tools

### Code Quality
- **Ruff** (0.12.11)
  - Fast Python linter and formatter
  - Enforces PEP8 style rules
  - Configured with specific linting rules and settings
  - Supports import sorting and line length management
- Type hints support (Python 3.12+)
- Code documentation standards

### Testing
- Django test framework
- Unit and integration tests
- Mocking and test utilities

### Version Control
- Git for version control
- Branching strategies (implied by development workflow)

### Documentation
- Markdown documentation
- Code comments and docstrings
- README files for components

## Configuration Management

### Environment Variables
- `.env` files for configuration
- Environment-specific settings
- Secret management and API keys

### Settings Management
- Django settings module
- Configuration separation between development and production
- Dynamic configuration loading

## Best Practices Implemented

### Security
- Input validation and sanitization
- SQL injection prevention (Django ORM)
- XSS protection
- CSRF protection
- Secure session management

### Performance
- Database indexing and optimization
- Query optimization
- Caching with Redis
- Connection pooling with PgBouncer

### Scalability
- Horizontal scaling with multiple workers
- Load balancing support
- Distributed task execution
- Database connection pooling

### Maintainability
- Modular code structure
- Clear separation of concerns
- Comprehensive error handling
- Logging and monitoring

## Skills Required for Contribution

### Backend Development
- Django framework development
- Python programming
- Database design and optimization
- API development (REST)

### Security
- Web vulnerability scanning
- Security tool integration
- Security best practices
- Threat modeling

### DevOps
- Docker containerization
- CI/CD pipelines (implied)
- Infrastructure as Code
- Monitoring and logging

### Frontend Development
- HTML/CSS/JavaScript
- Bootstrap framework
- AJAX and REST API integration
- Real-time updates (WebSocket)

## Learning Resources

### Django
- [Django Official Documentation](https://docs.djangoproject.com/)
- [Django REST Framework Guide](https://www.django-rest-framework.org/)

### Python
- [Python Official Documentation](https://docs.python.org/)

### Security
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Secator Documentation](https://secator.readthedocs.io/)

### Docker
- [Docker Documentation](https://docs.docker.com/)

---

*Last Updated: 2026*
*Version: reNgine-ng*