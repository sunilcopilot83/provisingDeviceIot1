using System.Text.Json;
using System.Text.Json.Serialization;

namespace ProvisioningService.Api.Models;

public class ProvisioningRequestJsonConverter : JsonConverter<ProvisioningRequest>
{
    public override ProvisioningRequest? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType != JsonTokenType.StartObject)
        {
            throw new JsonException("Provisioning payload must be a JSON object.");
        }

        var request = new ProvisioningRequest();

        while (reader.Read())
        {
            if (reader.TokenType == JsonTokenType.EndObject)
            {
                return request;
            }

            if (reader.TokenType != JsonTokenType.PropertyName)
            {
                throw new JsonException("Invalid provisioning payload.");
            }

            var propertyName = reader.GetString();
            reader.Read();
            var propertyValue = reader.TokenType == JsonTokenType.Null ? string.Empty : reader.GetString() ?? string.Empty;

            switch (propertyName)
            {
                case "device_id":
                case "deviceId":
                    request.DeviceId = propertyValue;
                    break;
                case "bootstrap_token":
                case "bootstrapToken":
                    request.BootstrapToken = propertyValue;
                    break;
                case "csr":
                    request.Csr = propertyValue;
                    break;
                default:
                    if (reader.TokenType is JsonTokenType.StartArray or JsonTokenType.StartObject)
                    {
                        reader.Skip();
                    }

                    break;
            }
        }

        throw new JsonException("Incomplete provisioning payload.");
    }

    public override void Write(Utf8JsonWriter writer, ProvisioningRequest value, JsonSerializerOptions options)
    {
        writer.WriteStartObject();
        writer.WriteString("device_id", value.DeviceId);
        writer.WriteString("bootstrap_token", value.BootstrapToken);
        writer.WriteString("csr", value.Csr);
        writer.WriteEndObject();
    }
}
