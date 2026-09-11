using System.Text.Json.Serialization;

namespace ProvisioningService.Api.Models;

public class ProvisioningResponse
{
    /// <example>-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----</example>
    [JsonPropertyName("device_certificate")]
    public string DeviceCertificate { get; set; } = string.Empty;
}
