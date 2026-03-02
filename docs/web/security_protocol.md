# Aegis Security & Authentication Protocol

## 1. Authentication & Token Management
- **Mechanism**: Use JWT (JSON Web Tokens) for session management.
- **Secure Storage**: 
  - **Access Tokens**: Store in-memory (JS state).
  - **Refresh Tokens**: Store in `HttpOnly`, `Secure`, `SameSite=Strict` cookies. This prevents XSS attacks from accessing the session.
- **CSRF Protection**: Implement Anti-CSRF tokens for any state-changing `POST` requests.

## 2. API Protection (Gateway Layer)
- **Rate Limiting**: Implement a "sliding window" rate limiter (e.g., Upstash or Redis) to limit users to X verifications per minute.
- **Payload Validation**: 
  - Strictly enforce the `VerifyRequestModel` schema from `aegis_sdk.py`.
  - Max Payload Size: Reject any JSON body larger than 1MB to prevent DoS attacks.
- **CORS Policy**: Restrict `Access-Control-Allow-Origin` to only the specific production domain of the Aegis Playground.

## 3. Code & Trace Protection
- **Sanitization**: Before sending traces to the Rust API, the SDK/Frontend must scrub common PII patterns (emails, passwords) unless explicitly part of the test case.
- **Input Filtering**: Use Zod to sanitize all strings in the "Policy Builder" to prevent injection attacks into the Rust `engine.rs` logic.
- **Environment Secrets**: API keys for the demo environment must be managed via `process.env` and never exposed in client-side bundles.

## 4. Rust Backend Integration
- **Auth Middleware**: Update `verifier/src/main.rs` to include an `AuthLayer` that validates the JWT from the cookie/header before calling `verify_trace`.
- **Request ID**: Attach a unique UUID to every verification request to allow for end-to-end audit logging between the frontend and the Rust backend.
