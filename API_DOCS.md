# Path2Root API Documentation

All API endpoints are prefixed with `/api`.

## Authentication

### `POST /api/auth/register`
Creates a new operator account.
- **Request Body**:
  ```json
  { "username": "admin", "password": "securepassword" }
  ```
- **Response**:
  ```json
  { "token": "JWT_TOKEN", "role": "operator" }
  ```

### `POST /api/auth/login`
Authenticates an existing operator.
- **Request Body**:
  ```json
  { "username": "admin", "password": "securepassword" }
  ```
- **Response**:
  ```json
  { "token": "JWT_TOKEN", "role": "operator" }
  ```

## Scanning & Analysis

### `POST /api/scan`
Launches a network scan and analysis.
- **Request Body**:
  ```json
  {
    "target": "127.0.0.1",
    "patches": [],
    "lang": "en"
  }
  ```
- **Response**:
  ```json
  {
    "graph": { "nodes": [...], "edges": [...] },
    "paths": [...],
    "risk_summary": { ... },
    "suggestions": [...]
  }
  ```

### `POST /api/mission`
Simulates an autonomous bounty mission.
- **Request Body**:
  ```json
  { "target": "example.com", "lang": "fr" }
  ```
- **Response**:
  ```json
  {
    "id": "MISSION_ID",
    "status": "Paid",
    "logs": [...]
  }
  ```

### `POST /api/chat`
Interacts with the offensive AI companion.
- **Request Body**:
  ```json
  { "message": "How to exploit this?", "lang": "en" }
  ```
- **Response**:
  ```json
  { "reply": "I recommend analyzing the critical path..." }
  ```
