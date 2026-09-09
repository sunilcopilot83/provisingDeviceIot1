using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;
using ProvisioningService.Api.Models;

namespace ProvisioningService.Api.Services;

public class InMemoryProvisioningService : IProvisioningService
{
    private const string GenericRejection = "provisioning request rejected";

    private readonly ConcurrentDictionary<string, DeviceRecord> _deviceRecords = new();

    public Task<ManufacturingDeviceResponse> RegisterDeviceAsync(ManufacturingDeviceRequest request, CancellationToken cancellationToken = default)
    {
        var normalizedDeviceId = NormalizeDeviceId(request.DeviceId);

        _deviceRecords[normalizedDeviceId] = new DeviceRecord
        {
            BootstrapTokenHash = HashToken(request.BootstrapToken),
            Used = false,
        };

        return Task.FromResult(new ManufacturingDeviceResponse
        {
            Status = "registered",
            DeviceId = normalizedDeviceId,
        });
    }

    public Task<ProvisioningResult> ProvisionDeviceAsync(ProvisioningRequest request, CancellationToken cancellationToken = default)
    {
        var normalizedDeviceId = NormalizeDeviceId(request.DeviceId);

        if (!_deviceRecords.TryGetValue(normalizedDeviceId, out var record))
        {
            return Task.FromResult(Rejected(400));
        }

        if (record.Used)
        {
            return Task.FromResult(Rejected(400));
        }

        if (!TokenMatches(record.BootstrapTokenHash, request.BootstrapToken))
        {
            return Task.FromResult(Rejected(400));
        }

        if (string.IsNullOrWhiteSpace(request.Csr))
        {
            return Task.FromResult(Rejected(400));
        }

        record.Used = true;

        return Task.FromResult(new ProvisioningResult
        {
            StatusCode = 200,
            Response = new ProvisioningResponse
            {
                DeviceCertificate = BuildCertificate(normalizedDeviceId),
            },
        });
    }

    private static ProvisioningResult Rejected(int statusCode) => new()
    {
        StatusCode = statusCode,
        Error = GenericRejection,
    };

    private static string NormalizeDeviceId(string deviceId) => deviceId.Trim().ToUpperInvariant();

    private static byte[] HashToken(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));

    private static bool TokenMatches(byte[] expectedHash, string suppliedToken)
    {
        var suppliedHash = HashToken(suppliedToken);
        return CryptographicOperations.FixedTimeEquals(expectedHash, suppliedHash);
    }

    private static string BuildCertificate(string deviceId)
    {
        var serial = Guid.NewGuid().ToString("N");
        var payload = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{deviceId}:{serial}:{DateTimeOffset.UtcNow:O}"));
        return $"-----BEGIN CERTIFICATE-----\n{payload}\n-----END CERTIFICATE-----";
    }

    private class DeviceRecord
    {
        public byte[] BootstrapTokenHash { get; init; } = Array.Empty<byte>();

        public bool Used { get; set; }
    }
}
