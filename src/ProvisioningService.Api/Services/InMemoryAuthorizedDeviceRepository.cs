using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace ProvisioningService.Api.Services;

public class InMemoryAuthorizedDeviceRepository : IAuthorizedDeviceRepository
{
    private readonly ConcurrentDictionary<string, AuthorizedDeviceRecord> _deviceRecords = new(StringComparer.OrdinalIgnoreCase);

    public Task<AuthorizedDeviceRecord?> GetAuthorizedDeviceAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        _deviceRecords.TryGetValue(deviceId, out var record);
        return Task.FromResult(record);
    }

    public Task MarkProvisionedAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        if (_deviceRecords.TryGetValue(deviceId, out var record))
        {
            record.Provisioned = true;
        }

        return Task.CompletedTask;
    }

    public Task UpsertAuthorizedDeviceAsync(string deviceId, string bootstrapToken, CancellationToken cancellationToken = default)
    {
        _deviceRecords[deviceId] = new AuthorizedDeviceRecord
        {
            BootstrapTokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(bootstrapToken)),
            Provisioned = false,
        };

        return Task.CompletedTask;
    }
}
