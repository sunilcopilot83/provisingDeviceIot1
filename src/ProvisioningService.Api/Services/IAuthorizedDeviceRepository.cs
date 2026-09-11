namespace ProvisioningService.Api.Services;

public interface IAuthorizedDeviceRepository
{
    Task<AuthorizedDeviceRecord?> GetAuthorizedDeviceAsync(string deviceId, CancellationToken cancellationToken = default);

    Task MarkProvisionedAsync(string deviceId, CancellationToken cancellationToken = default);

    Task UpsertAuthorizedDeviceAsync(string deviceId, string bootstrapToken, CancellationToken cancellationToken = default);
}

public class AuthorizedDeviceRecord
{
    public byte[] BootstrapTokenHash { get; init; } = Array.Empty<byte>();

    public bool Provisioned { get; set; }
}
