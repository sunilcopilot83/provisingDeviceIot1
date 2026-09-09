# ProvisioningService.Api

This repository now hosts an ASP.NET Core Web API microservice that maps the prior provisioning-function flow into controller-based endpoints.

The original Azure Functions Python artifacts are preserved under:

- `backend/provisioning-function/`

## Prerequisites

- .NET SDK 10.0 (or latest SDK that supports `net10.0`)

## Run locally

```bash
dotnet restore src/ProvisioningService.Api/ProvisioningService.Api.csproj
dotnet build src/ProvisioningService.Api/ProvisioningService.Api.csproj
dotnet run --project src/ProvisioningService.Api/ProvisioningService.Api.csproj
```

## Swagger

When the app starts, open:

- `http://localhost:5218/swagger` (HTTP profile)
- or the HTTPS URL shown in console output (usually `https://localhost:7073/swagger`)

## API endpoints

- `POST /api/v1/manufacturing/device`
  - Registers/updates a device bootstrap token.
- `POST /api/v1/provision`
  - Validates bootstrap token and returns a `deviceCertificate` payload.

## Sample request payloads

### 1) Register device

`POST /api/v1/manufacturing/device`

```json
{
  "deviceId": "AA:BB:CC:DD:EE:FF",
  "bootstrapToken": "boot-token-123"
}
```

Sample response shape:

```json
{
  "status": "registered",
  "deviceId": "AA:BB:CC:DD:EE:FF"
}
```

### 2) Provision certificate

`POST /api/v1/provision`

```json
{
  "deviceId": "AA:BB:CC:DD:EE:FF",
  "bootstrapToken": "boot-token-123",
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----"
}
```

Expected success response shape:

```json
{
  "deviceCertificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

If validation fails, the API returns:

```json
{
  "error": "provisioning request rejected"
}
```
