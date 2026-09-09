namespace ProvisioningService.Api.Models;

public class ProvisioningResponse
{
    /// <example>-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----</example>
    public string DeviceCertificate { get; set; } = string.Empty;
}
