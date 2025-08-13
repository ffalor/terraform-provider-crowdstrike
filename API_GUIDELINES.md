# Terraform Resource Requirements & HTTP API Best Practices

This guide outlines what a Terraform resource needs from an API to be successfully implemented using the terraform-plugin-framework, along with proper HTTP method semantics and status code usage.

## Essential CRUD Operations

### Create Operation
The API must provide a way to create new resources and return:
- A unique, stable identifier for the resource
- The complete resource state
- **Status Code**: 201 (Created) for successful creation

### Read Operation
The API must provide a way to retrieve a resource by its ID and return:
- Complete resource state
- Consistent data structure every time
- **Status Codes**: 200 (OK) for found resources, 404 (Not Found) for non-existent resources

### Update Operation
The API must support modifying existing resources and return:
- Complete updated resource state
- Same data structure as create/read operations
- Proper handling of partial updates
- **Status Code**: 200 (OK) for successful updates

### Delete Operation
The API must provide a way to remove resources:
- Should return 204 (No Content) for successful deletion
- Should return 200 (OK) if providing deletion status information

## Critical Requirements

### 1. Stable Resource Identity
Resources must have immutable identifiers where the same physical resource always returns the same ID. IDs should not change during resource updates.

### 2. State Consistency
Read operations must return the same attributes as create/update operations. All attributes visible to clients must be consistently available with no "hidden" state that clients cannot track.

**Example inconsistent response:**
```json
// POST response (create)
{
  "id": "123",
  "name": "resource",
  "status": "active",
  "metadata": {...}
}

// PATCH response (update) - missing fields!
{
  "id": "123", 
  "name": "updated-resource"
}
```

### 3. Idempotency
- Multiple identical requests should produce the same result
- Updates with the same values should be safe to repeat
- Deletes should succeed even if resource doesn't exist

### 4. Complete State Information
API responses must include all resource attributes with no partial or incomplete state representations.

### 5. Partial Updates Support
PATCH endpoints should accept partial resource representations where only modified fields need to be provided in PATCH requests. However, PATCH responses must still return complete resource state.

**Example:**
```json
// PATCH request (partial)
{
  "description": "Updated description"
}

// PATCH response (complete state - only description changed)
{
  "id": "123",
  "name": "resource",
  "description": "Updated description",
  "status": "active",
  "metadata": {...}
}
```

## Error Handling Requirements

### Clear Error Messages
- Provide actionable error information
- Include field-specific validation errors when possible
- Use consistent error response structure

**Example:**
```
✅ Good: "Name is required and must be between 3-50 characters"
❌ Bad: "Invalid input"
```

### Error Status Codes
- **400 Bad Request**: Malformed request syntax or invalid request message
- **404 Not Found**: Resource doesn't exist
- **409 Conflict**: Request conflicts with current resource state (e.g., duplicate creation)
- **422 Unprocessable Entity**: Valid request format but semantic validation failed
- **500 Internal Server Error**: Unexpected server error
- **503 Service Unavailable**: Temporary server unavailability

## SDK Generation Requirements

Your API specification must accurately reflect actual endpoint behavior. The goFalcon SDK is generated from your API spec, and the Terraform Provider relies on goFalcon SDK.

If specifications do not match the implementation, the following issues may occur:
- Broken SDK methods that return unexpected status codes
- Missing fields or incorrect data structures
- Runtime errors in applications using the SDK

### Tags & OperationId Naming
Tags group related endpoints and become service collections in goFalcon SDK. Use meaningful names that logically group functionality. OperationId becomes the method name in the generated SDK and should be descriptive and follow consistent naming patterns.

**Tag Examples:**
```
✅ Good: "tags": ["FileVantage"] → client.FileVantage.<method>
❌ Bad: "tags": ["API"] → client.API.<method>
```

**OperationId Examples:**
```
✅ Good: "operationId": "CreatePolicy" → client.FileVantage.CreatePolicy()
❌ Bad: "operationId": "PostPolicyCreate" → client.API.PostPolicyCreate()
```

**Full Example:**
```json
{
  "paths": {
    "/filevantage/policies/v1": {
      "post": {
        "tags": ["FileVantage"],
        "operationId": "CreatePolicy",
        "summary": "Create a new FileVantage policy"
      }
    }
  }
}
```
Results in: `client.FileVantage.CreatePolicy()`

### Model Naming
Models defined in request/response schemas become structs in the generated SDK. Use descriptive names that clearly indicate the model's purpose and avoid generic or auto-generated names. 

**Critical**: Model names should not be changed once published. Go is a typed language, so model name changes are breaking changes that will cause any code using the old struct name to fail to compile.

**Examples:**
```
✅ Good: "DetectionEnrichment" → DetectionEnrichment struct
❌ Bad: "CustomType1942251022" → CustomType1942251022 struct
```

### Response Model Consistency
GET, POST, PUT, and PATCH endpoints for the same resource should use the same response model since all these operations return the complete resource state with identical fields. Using different models for the same resource creates inconsistency and confusion in the SDK. 

Additionally, avoid operation-specific naming (e.g., "CreateResponse") when the model is used across multiple operations, and avoid implementation prefixes (e.g., "Rest") in model names.

**Good Example - Consistent Model:**
```
✅ All endpoints use "PolicyResponse" model:
   GET /policies/{id} → PolicyResponse
   POST /policies → PolicyResponse  
   PATCH /policies/{id} → PolicyResponse
```

**Bad Examples:**
```
❌ Different models per operation:
   GET /policies/{id} → PolicyDetailsResponse
   POST /policies → CreatePolicyResponse
   PATCH /policies/{id} → UpdatePolicyResponse

❌ Poor naming:
   All endpoints use "RestAWSAccountCreateResponseExtV1"
   - Contains "Rest" implementation detail
   - Contains "Create" but used for GET/PATCH too
   - Results in confusing SDK: models.RestAWSAccountCreateResponseExtV1
```

**Common Specification Issues:**
- **Status Code Mismatches**: Spec says 200 but endpoint returns 201, causing SDK error handling to treat successful operations as failures
  - Example: `POST /policy/entities/sv-exclusions/v1` returns 201 but spec says 200
- **Response Schema Mismatches**: Different fields between spec and actual response, resulting in SDK structs with missing or incorrect fields.
- **Field Type Mismatches**: Spec defines field as string but endpoint returns integer, causing SDK type conversion errors and runtime panics
