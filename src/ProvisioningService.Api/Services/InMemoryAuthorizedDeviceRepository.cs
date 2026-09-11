using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text;

namespace ProvisioningService.Api.Services;

public class InMemoryAuthorizedDeviceRepository : IAuthorizedDeviceRepository
{
    private readonly ConcurrentDictionary<string, AuthorizedDeviceRecord> _deviceRecords = new(StringComparer.OrdinalIgnoreCase);
    private readonly Lock _syncRoot = new();

    public Task<AuthorizedDeviceRecord?> GetAuthorizedDeviceAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        lock (_syncRoot)
        {
            _deviceRecords.TryGetValue(deviceId, out var record);
            return Task.FromResult(record);
        }
    }

    public Task ResetProvisioningAsync(string deviceId, CancellationToken cancellationToken = default)
    {
        lock (_syncRoot)
        {
            if (_deviceRecords.TryGetValue(deviceId, out var record))
            {
                record.Provisioned = false;
            }
        }

        return Task.CompletedTask;
    }

    public Task<ProvisioningAuthorizationStatus> TryBeginProvisioningAsync(
        string deviceId,
        string bootstrapToken,
        CancellationToken cancellationToken = default)
    {
        lock (_syncRoot)
        {
            if (!_deviceRecords.TryGetValue(deviceId, out var record))
            {
                return Task.FromResult(ProvisioningAuthorizationStatus.UnknownDeviceOrTokenMismatch);
            }

            var suppliedHash = SHA256.HashData(Encoding.UTF8.GetBytes(bootstrapToken));
            if (!CryptographicOperations.FixedTimeEquals(record.BootstrapTokenHash, suppliedHash))
            {
                return Task.FromResult(ProvisioningAuthorizationStatus.UnknownDeviceOrTokenMismatch);
            }

            if (record.Provisioned)
            {
                return Task.FromResult(ProvisioningAuthorizationStatus.AlreadyProvisioned);
            }

            record.Provisioned = true;
            return Task.FromResult(ProvisioningAuthorizationStatus.Authorized);
        }
    }

    public Task UpsertAuthorizedDeviceAsync(string deviceId, string bootstrapToken, CancellationToken cancellationToken = default)
    {
        lock (_syncRoot)
        {
            var existingProvisionedState =
                _deviceRecords.TryGetValue(deviceId, out var existingRecord) &&
                existingRecord.Provisioned;

            _deviceRecords[deviceId] = new AuthorizedDeviceRecord
            {
                BootstrapTokenHash = SHA256.HashData(Encoding.UTF8.GetBytes(bootstrapToken)),
                Provisioned = existingProvisionedState,
            };
        }

        return Task.CompletedTask;
    }
}
