using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace ProvisioningService.Api.Models;

public class ProvisioningRequest
{
    /// <example>AA:BB:CC:DD:EE:FF</example>
    [Required]
    [MinLength(3)]
    [JsonPropertyName("device_id")]
    public string DeviceId { get; set; } = string.Empty;

    /// <example>0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789AB</example>
    [Required]
    [StringLength(130, MinimumLength = 130)]
    [JsonPropertyName("bootstrap_token")]
    public string BootstrapToken { get; set; } = string.Empty;

    /// <example>-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----</example>
    [Required]
    [MinLength(10)]
    [JsonPropertyName("csr")]
    public string Csr { get; set; } = string.Empty;
}
