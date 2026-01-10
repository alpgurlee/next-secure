# Contributing to next-secure

First off, thank you for considering contributing to next-secure! It's people like you that make next-secure such a great tool.

## Code of Conduct

By participating in this project, you are expected to uphold our Code of Conduct: be respectful, inclusive, and constructive.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples** (code snippets, error messages)
- **Describe the behavior you observed and expected**
- **Include your environment** (Node.js version, Next.js version, OS)

### Suggesting Features

Feature requests are welcome! Please provide:

- **A clear and descriptive title**
- **Detailed description** of the proposed feature
- **Use cases** - why would this be useful?
- **Possible implementation** (optional)

### Pull Requests

1. **Fork the repo** and create your branch from `main`
2. **Install dependencies**: `npm install`
3. **Make your changes**
4. **Add tests** for any new functionality
5. **Run tests**: `npm test`
6. **Run linting**: `npm run lint`
7. **Update documentation** if needed
8. **Submit a pull request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/next-secure.git
cd next-secure

# Install dependencies
npm install

# Run tests in watch mode
npm test

# Build the project
npm run build

# Run linting
npm run lint

# Type checking
npm run typecheck
```

## Project Structure

```
next-secure/
├── src/
│   ├── core/           # Core types and errors
│   ├── middleware/     # Middleware implementations
│   │   ├── rate-limit/ # Rate limiting
│   │   ├── auth/       # Authentication
│   │   ├── csrf/       # CSRF protection
│   │   └── headers/    # Security headers
│   └── utils/          # Utility functions
├── tests/
│   ├── unit/           # Unit tests
│   └── integration/    # Integration tests
└── examples/           # Example projects
```

## Coding Standards

### TypeScript

- Use strict TypeScript configuration
- Prefer explicit types over `any`
- Use type imports: `import type { ... }`

### Style

- Use Prettier for formatting (runs automatically)
- Follow ESLint rules
- Use meaningful variable and function names
- Add JSDoc comments for public APIs

### Testing

- Write tests for all new functionality
- Aim for high test coverage
- Use descriptive test names
- Test edge cases

### Commits

- Use clear, descriptive commit messages
- Reference issues when relevant: `fix: rate limit header issue (#123)`
- Keep commits focused on a single change

## Pull Request Process

1. Update the README.md if you're changing functionality
2. Update the CHANGELOG.md with your changes
3. Ensure all tests pass
4. Request review from maintainers
5. Address any feedback

## Release Process

Releases are handled by maintainers using Changesets:

```bash
# Create a changeset
npx changeset

# Version packages
npx changeset version

# Publish
npx changeset publish
```

## Questions?

Feel free to open an issue with your question or reach out to the maintainers.

Thank you for contributing! 🎉
