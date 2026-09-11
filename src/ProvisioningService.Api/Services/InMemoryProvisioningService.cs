using System.Security.Cryptography;
using System.Text;
using ProvisioningService.Api.Models;

namespace ProvisioningService.Api.Services;

public class InMemoryProvisioningService(
    IAuthorizedDeviceRepository authorizedDeviceRepository,
    ICertificateSigningRequestValidator certificateSigningRequestValidator,
    IDeviceCertificateSigner deviceCertificateSigner,
    ILogger<InMemoryProvisioningService> logger) : IProvisioningService
{
    private const string GenericRejection = "provisioning request rejected";

    public async Task<ManufacturingDeviceResponse> RegisterDeviceAsync(ManufacturingDeviceRequest request, CancellationToken cancellationToken = default)
    {
        var normalizedDeviceId = NormalizeDeviceId(request.DeviceId);
        var tokenFingerprint = CreateTokenFingerprint(request.BootstrapToken);

        await authorizedDeviceRepository.UpsertAuthorizedDeviceAsync(normalizedDeviceId, request.BootstrapToken, cancellationToken);

        logger.LogInformation(
            "Registered bootstrap token for {device_id} with fingerprint {bootstrap_token_fingerprint}",
            normalizedDeviceId,
            tokenFingerprint);

        return new ManufacturingDeviceResponse
        {
            Status = "registered",
            DeviceId = normalizedDeviceId,
        };
    }

    public async Task<ProvisioningResult> ProvisionDeviceAsync(ProvisioningRequest request, CancellationToken cancellationToken = default)
    {
        var normalizedDeviceId = NormalizeDeviceId(request.DeviceId);
        var tokenFingerprint = CreateTokenFingerprint(request.BootstrapToken);

        logger.LogInformation(
            "Provisioning attempt for {device_id} with bootstrap token fingerprint {bootstrap_token_fingerprint}",
            normalizedDeviceId,
            tokenFingerprint);

        var record = await authorizedDeviceRepository.GetAuthorizedDeviceAsync(normalizedDeviceId, cancellationToken);

        if (record is null || !TokenMatches(record.BootstrapTokenHash, request.BootstrapToken))
        {
            logger.LogWarning(
                "Provisioning rejected for {device_id} with fingerprint {bootstrap_token_fingerprint}: unauthorized device or bootstrap token mismatch",
                normalizedDeviceId,
                tokenFingerprint);

            return Rejected(StatusCodes.Status403Forbidden);
        }

        if (record.Provisioned)
        {
            logger.LogWarning(
                "Provisioning rejected for {device_id} with fingerprint {bootstrap_token_fingerprint}: bootstrap token already used",
                normalizedDeviceId,
                tokenFingerprint);

            return Rejected(StatusCodes.Status409Conflict);
        }

        if (!certificateSigningRequestValidator.TryValidate(request.Csr, out var certificateRequest))
        {
            logger.LogWarning(
                "Provisioning rejected for {device_id} with fingerprint {bootstrap_token_fingerprint}: invalid CSR",
                normalizedDeviceId,
                tokenFingerprint);

            return Rejected(StatusCodes.Status400BadRequest);
        }

        var deviceCertificate = deviceCertificateSigner.SignDeviceCertificate(normalizedDeviceId, certificateRequest);
        await authorizedDeviceRepository.MarkProvisionedAsync(normalizedDeviceId, cancellationToken);

        logger.LogInformation(
            "Provisioning succeeded for {device_id} with bootstrap token fingerprint {bootstrap_token_fingerprint}",
            normalizedDeviceId,
            tokenFingerprint);

        return new ProvisioningResult
        {
            StatusCode = StatusCodes.Status200OK,
            Response = new ProvisioningResponse
            {
                DeviceCertificate = deviceCertificate,
            },
        };
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

    private static string CreateTokenFingerprint(string token)
    {
        var hash = Convert.ToHexString(HashToken(token));
        return hash[..12];
    }
}
