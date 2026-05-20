# Changelog

## [0.3.0-alpha.1](https://github.com/credat/credat-mcp/compare/v0.2.0-alpha.1...v0.3.0-alpha.1) (2026-03-22)


### ⚠ BREAKING CHANGES

* `isAuthenticated()` and `getSessionAuth()` are now async (return Promise) to support async store backends.

### Features

* pluggable stores, SQLite backend, hooks, constraints, async APIs ([87f243e](https://github.com/credat/credat-mcp/commit/87f243e604d640856fb0ea3c27f16121e671e95d))

## [0.2.0-alpha.1](https://github.com/credat/credat-mcp/compare/v0.1.2-alpha.1...v0.2.0-alpha.1) (2026-03-19)


### ⚠ BREAKING CHANGES

* peer dependency changed from credat to @credat/sdk

### Features

* migrate from credat to @credat/sdk ([fd07b17](https://github.com/credat/credat-mcp/commit/fd07b178b181dcd228e58d1579c77fef9740a075))

## [0.1.2-alpha.1](https://github.com/credat/credat-mcp/compare/v0.1.1-alpha.1...v0.1.2-alpha.1) (2026-03-19)


### Bug Fixes

* add --access public to npm publish for scoped package ([c205247](https://github.com/credat/credat-mcp/commit/c205247d1c3e51a67e5156933a6a0367d6fc7a26))

## [0.1.1-alpha.1](https://github.com/credat/credat-mcp/compare/v0.1.0-alpha.1...v0.1.1-alpha.1) (2026-03-19)


### Features

* initial release of @credat/mcp ([c785837](https://github.com/credat/credat-mcp/commit/c78583758805cc23fe64befd7f3f59b14b7df1d1))


### Bug Fixes

* biome v2 config and formatting ([8e6e3f1](https://github.com/credat/credat-mcp/commit/8e6e3f108a742b0e607b806ea918dba5fc465938))
