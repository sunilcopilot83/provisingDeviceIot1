using Microsoft.AspNetCore.Mvc;
using ProvisioningService.Api.Models;
using ProvisioningService.Api.Services;

namespace ProvisioningService.Api.Controllers;

[ApiController]
[Route("api/v1")]
public class ProvisioningController(IProvisioningService provisioningService) : ControllerBase
{
    /// <summary>
    /// Registers or updates a device bootstrap token for manufacturing-time setup.
    /// </summary>
    /// <remarks>
    /// Sample request:
    ///
    ///     POST /api/v1/manufacturing/device
    ///     {
    ///         "deviceId": "AA:BB:CC:DD:EE:FF",
    ///         "bootstrapToken": "boot-token-123"
    ///     }
    /// </remarks>
    [HttpPost("manufacturing/device")]
    [ProducesResponseType(typeof(ManufacturingDeviceResponse), StatusCodes.Status200OK)]
    public async Task<ActionResult<ManufacturingDeviceResponse>> RegisterDevice(
        [FromBody] ManufacturingDeviceRequest request,
        CancellationToken cancellationToken)
    {
        var response = await provisioningService.RegisterDeviceAsync(request, cancellationToken);
        return Ok(response);
    }

    /// <summary>
    /// Provisions a device certificate after bootstrap token validation.
    /// </summary>
    /// <remarks>
    /// Sample request:
    ///
    ///     POST /api/v1/provision
    ///     {
    ///         "deviceId": "AA:BB:CC:DD:EE:FF",
    ///         "bootstrapToken": "boot-token-123",
    ///         "csr": "-----BEGIN CERTIFICATE REQUEST-----\\nMIIB...\\n-----END CERTIFICATE REQUEST-----"
    ///     }
    /// </remarks>
    [HttpPost("provision")]
    [ProducesResponseType(typeof(ProvisioningResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(object), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(object), StatusCodes.Status500InternalServerError)]
    public async Task<ActionResult<ProvisioningResponse>> Provision(
        [FromBody] ProvisioningRequest request,
        CancellationToken cancellationToken)
    {
        var result = await provisioningService.ProvisionDeviceAsync(request, cancellationToken);

        if (result.Response is not null)
        {
            return StatusCode(result.StatusCode, result.Response);
        }

        return StatusCode(result.StatusCode, new { error = result.Error });
    }
}
