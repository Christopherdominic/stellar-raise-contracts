# Frontend Global Error Boundary

Technical reference for the React global error boundary built for the Stellar Raise frontend.

---

## Overview

`FrontendGlobalErrorBoundary` is a React class component that catches synchronous render-phase errors anywhere in its wrapped component tree. It prevents full application crashes, classifies errors as generic or smart-contract related, and renders an appropriate fallback UI with a recovery path.

```
Error thrown → getDerivedStateFromError (state) →
componentDidCatch (logging + onError callback) → fallback UI
```

---

## Component API

```tsx
import {
  FrontendGlobalErrorBoundary,
  ContractError,
  NetworkError,
  TransactionError,
} from '../components/frontend_global_error';
```

### Props

| Prop | Type | Required | Description |
|------|------|----------|-------------|
| `children` | `ReactNode` | No | Component tree to protect |
| `fallback` | `ReactNode` | No | Custom fallback UI; overrides built-in fallback entirely |
| `onError` | `(report: ErrorReport) => void` | No | Callback invoked with a sanitised error report on every caught error |

### ErrorReport shape

```ts
interface ErrorReport {
  message: string;
  stack: string | undefined;        // omitted in production
  componentStack: string | undefined; // omitted in production
  timestamp: string;                // ISO 8601
  isSmartContractError: boolean;
  errorName: string;
}
```

---

## Custom Error Classes

Use these to signal specific failure domains to the boundary:

```tsx
// Smart contract execution failure
throw new ContractError('Insufficient funds for transaction');

// Network / Horizon API failure
throw new NetworkError('Horizon endpoint unreachable');

// Transaction signing / submission failure
throw new TransactionError('User rejected transaction in wallet');
```

All three extend `Error` and are automatically classified as smart-contract errors by the boundary.

---

## Error Classification

The boundary classifies an error as a smart-contract error when:

1. It is an instance of `ContractError`, `NetworkError`, or `TransactionError`.
2. Its `name` or `message` contains any of these keywords (case-insensitive):
   `contract`, `stellar`, `soroban`, `transaction`, `blockchain`, `ledger`,
   `horizon`, `xdr`, `invoke`, `wallet`.

All other errors render the generic "Documentation Loading Error" fallback.

**Windowing caveat:** keyword matching runs on a bounded prefix of `error.name` + `error.message` (`MAX_CLASSIFICATION_INPUT_CHARS`, default 8192 UTF-16 code units). If a keyword appears only *after* that window, the error is treated as generic (safer default).

---

## Logging bounds (scripts & maintainability)

Exported constants and helpers cap string work so CI log shippers, browser consoles, and the main thread do not process unbounded error text:

| Export | Purpose |
|--------|---------|
| `MAX_CLASSIFICATION_INPUT_CHARS` | Max size of haystack for keyword classification |
| `MAX_REPORT_MESSAGE_CHARS` | Max `ErrorReport.message` for `onError` / telemetry |
| `MAX_REPORT_STACK_CHARS` | Max stack string in dev reports |
| `MAX_REPORT_COMPONENT_STACK_CHARS` | Max React component stack in dev reports |
| `MAX_DISPLAY_MESSAGE_CHARS` | Max characters in dev-only `<pre>` in the fallback UI |
| `MAX_ERROR_NAME_CHARS` | Max `ErrorReport.errorName` |
| `MAX_THROWN_VALUE_STRING_CHARS` | Max `String(unknown)` when normalising non-`Error` throwables |
| `truncateForBounds(s, maxCodeUnits)` | Shared truncation helper (appends `…` when trimmed) |
| `boundedClassificationHaystack(error)` | Lowercased, capped haystack for keyword scan |

Use the same helpers in build scripts or server middleware if you classify errors consistently with the UI.

---

## Fallback UIs

### Generic fallback
- ⚠️ icon
- Title: "Documentation Loading Error"
- "Try Again" and "Go Home" buttons

### Smart contract fallback
- 🔗 icon
- Title: "Smart Contract Error"
- Blockchain-specific guidance (wallet balance, connectivity)
- "Try Again" and "Go Home" buttons

### Dev-only error details
In `NODE_ENV !== 'production'`, a collapsible `<details>` element shows the raw error message to aid debugging. This section is hidden in production to prevent information disclosure.

---

## Usage

### Basic

```tsx
import { FrontendGlobalErrorBoundary } from '../components/frontend_global_error';

function App() {
  return (
    <FrontendGlobalErrorBoundary>
      <MainApplication />
    </FrontendGlobalErrorBoundary>
  );
}
```

### With custom fallback

```tsx
<FrontendGlobalErrorBoundary fallback={<div>Custom error UI</div>}>
  <MainApplication />
</FrontendGlobalErrorBoundary>
```

### With error reporting (Sentry example)

```tsx
import * as Sentry from '@sentry/react';

<FrontendGlobalErrorBoundary
  onError={(report) => Sentry.captureMessage(report.message, { extra: report })}
>
  <MainApplication />
</FrontendGlobalErrorBoundary>
```

### Throwing typed errors in contract components

```tsx
import { ContractError } from '../components/frontend_global_error';

async function contribute(amount: number) {
  try {
    await contract.invoke('contribute', { amount });
  } catch (err) {
    throw new ContractError(`Contribution failed: ${(err as Error).message}`);
  }
}
```

---

## Security Considerations

| Concern | Mitigation |
|---------|-----------|
| Information disclosure | Stack traces and component stacks are omitted from `ErrorReport` in production |
| XSS via error messages | Fallback UI renders error message as React text node (not `innerHTML`) |
| Sensitive contract data | Custom error classes should never embed private keys, XDR, or account secrets in the message |
| Async errors | The boundary does NOT catch errors in event handlers, `setTimeout`, or SSR — handle those separately |
| Log / script DoS | All reports and dev UI text go through `truncateForBounds` and `MAX_*` caps |
| Classification blind spot | Keywords beyond `MAX_CLASSIFICATION_INPUT_CHARS` are ignored; use typed errors (`ContractError`, etc.) for reliable routing |

---

## Limitations

- Cannot catch errors thrown inside the boundary's own `render` method.
- Does not catch async errors (event handlers, `Promise` rejections, `setTimeout`).
- Does not catch server-side rendering errors (use Next.js `_error.tsx` / `500.tsx` for those).
- Nested boundaries can be used for more granular isolation of subsections.

---

## Test Coverage

Tests live in `frontend/components/frontend_global_error.test.tsx` and
`frontend/utils/frontend_global_error.test.tsx` and cover:

- Custom error class instantiation and inheritance
- Normal (no-error) rendering
- Generic error fallback rendering and logging
- Smart contract error detection (10 keyword/type variants)
- Custom fallback prop (generic and contract errors)
- Recovery via "Try Again" (success and persistent-error cases)
- `onError` callback with structured report validation
- Accessibility (`role="alert"`, `aria-live`, `aria-label`, `aria-hidden`)
- Edge cases: empty message, TypeError, keyword matching
- **Logging bounds:** `truncateForBounds`, `boundedClassificationHaystack`, `ErrorReport` truncation, classification window, dev `<pre>` length

Run:

```bash
npx jest --testPathPatterns=frontend/components/frontend_global_error.test --coverage --collectCoverageFrom=frontend/components/frontend_global_error.tsx
```

Recent run: **63** tests passed; coverage for `frontend_global_error.tsx` ~**96%** statements, ~**97%** lines (see local `coverage/` output).

---

## Integration with Next.js

```tsx
// pages/_app.tsx
import GlobalErrorBoundary from '../components/frontend_global_error';

function MyApp({ Component, pageProps }) {
  return (
    <GlobalErrorBoundary>
      <Component {...pageProps} />
    </GlobalErrorBoundary>
  );
}
```

The boundary handles client-side render errors. `pages/500.tsx` handles server-side errors. Both should be present for full coverage.
