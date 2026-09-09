namespace ProvisioningService.Api.Models;

public class ManufacturingDeviceResponse
{
    public string Status { get; set; } = "registered";

    public string DeviceId { get; set; } = string.Empty;
}
