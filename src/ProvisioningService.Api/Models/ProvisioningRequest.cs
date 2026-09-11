using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace ProvisioningService.Api.Models;

/// <summary>
/// Provisioning request payload for a Jarvis device certificate.
/// </summary>
[JsonConverter(typeof(ProvisioningRequestJsonConverter))]
public class ProvisioningRequest : IValidatableObject
{
    /// <example>AA:BB:CC:DD:EE:FF</example>
    [JsonPropertyName("device_id")]
    [Required(AllowEmptyStrings = false)]
    [RegularExpression(@"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")]
    public string DeviceId { get; set; } = string.Empty;

    /// <example>boot-token-123</example>
    [JsonPropertyName("bootstrap_token")]
    [Required(AllowEmptyStrings = false)]
    public string BootstrapToken { get; set; } = string.Empty;

    /// <example>-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----</example>
    [JsonPropertyName("csr")]
    [Required(AllowEmptyStrings = false)]
    public string Csr { get; set; } = string.Empty;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!string.IsNullOrWhiteSpace(Csr) &&
            (!Csr.TrimStart().StartsWith("-----BEGIN CERTIFICATE REQUEST-----", StringComparison.Ordinal) ||
             !Csr.TrimEnd().EndsWith("-----END CERTIFICATE REQUEST-----", StringComparison.Ordinal)))
        {
            yield return new ValidationResult(
                "The csr field must be a PEM encoded certificate signing request.",
                [nameof(Csr)]);
        }
    }
}
