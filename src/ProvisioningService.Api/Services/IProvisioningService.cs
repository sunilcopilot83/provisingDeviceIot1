using ProvisioningService.Api.Models;

namespace ProvisioningService.Api.Services;

public interface IProvisioningService
{
    Task<ManufacturingDeviceResponse> RegisterDeviceAsync(ManufacturingDeviceRequest request, CancellationToken cancellationToken = default);

    Task<ProvisioningResult> ProvisionDeviceAsync(ProvisioningRequest request, CancellationToken cancellationToken = default);
}

public class ProvisioningResult
{
    public int StatusCode { get; init; }

    public ProvisioningResponse? Response { get; init; }

    public string? Error { get; init; }
}
