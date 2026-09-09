using System.ComponentModel.DataAnnotations;

namespace ProvisioningService.Api.Models;

public class ProvisioningRequest
{
    /// <example>AA:BB:CC:DD:EE:FF</example>
    [Required]
    [MinLength(3)]
    public string DeviceId { get; set; } = string.Empty;

    /// <example>boot-token-123</example>
    [Required]
    [MinLength(3)]
    public string BootstrapToken { get; set; } = string.Empty;

    /// <example>-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----</example>
    [Required]
    [MinLength(10)]
    public string Csr { get; set; } = string.Empty;
}
