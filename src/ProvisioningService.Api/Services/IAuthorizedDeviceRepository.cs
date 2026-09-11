namespace ProvisioningService.Api.Services;

public interface IAuthorizedDeviceRepository
{
    Task<AuthorizedDeviceRecord?> GetAuthorizedDeviceAsync(string deviceId, CancellationToken cancellationToken = default);

    Task ResetProvisioningAsync(string deviceId, CancellationToken cancellationToken = default);

    Task<ProvisioningAuthorizationStatus> TryBeginProvisioningAsync(
        string deviceId,
        string bootstrapToken,
        CancellationToken cancellationToken = default);

    Task UpsertAuthorizedDeviceAsync(string deviceId, string bootstrapToken, CancellationToken cancellationToken = default);
}

public enum ProvisioningAuthorizationStatus
{
    Authorized,
    UnknownDeviceOrTokenMismatch,
    AlreadyProvisioned,
}

public class AuthorizedDeviceRecord
{
    public byte[] BootstrapTokenHash { get; init; } = Array.Empty<byte>();

    public bool Provisioned { get; set; }

    public Lock SyncRoot { get; } = new();
}
