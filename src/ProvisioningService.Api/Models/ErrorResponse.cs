using System.Text.Json.Serialization;

namespace ProvisioningService.Api.Models;

public class ErrorResponse
{
    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;

    public static ErrorResponse From(string error) => new()
    {
        Error = error,
    };
}
