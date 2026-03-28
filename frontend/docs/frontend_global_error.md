# `frontend_global_error`

## Where to read

Full specification, security notes, logging bounds, and CI commands are in the repository root:

**[docs/frontend_global_error.md](../../docs/frontend_global_error.md)**

## Source files

| Artifact | Path |
|----------|------|
| Implementation | [`frontend/components/frontend_global_error.tsx`](../components/frontend_global_error.tsx) |
| Tests | [`frontend/components/frontend_global_error.test.tsx`](../components/frontend_global_error.test.tsx) |

## Quick test

From the `stellar-raise-contracts` package root:

```bash
npx jest --testPathPatterns=frontend/components/frontend_global_error.test --coverage --collectCoverageFrom=frontend/components/frontend_global_error.tsx
```
