using System.Text.Json.Serialization;

namespace ProvisioningService.Api.Models;

public class ProvisioningErrorResponse
{
    [JsonPropertyName("error")]
    public string Error { get; set; } = string.Empty;
}
