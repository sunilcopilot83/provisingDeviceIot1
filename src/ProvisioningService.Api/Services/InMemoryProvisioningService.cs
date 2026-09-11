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
        var safeDeviceId = SanitizeForLog(normalizedDeviceId);
        var tokenFingerprint = CreateTokenFingerprint(request.BootstrapToken);

        await authorizedDeviceRepository.UpsertAuthorizedDeviceAsync(normalizedDeviceId, request.BootstrapToken, cancellationToken);

        logger.LogInformation(
            "Registered bootstrap token for {device_id} with fingerprint {bootstrap_token_fingerprint}",
            safeDeviceId,
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
        var safeDeviceId = SanitizeForLog(normalizedDeviceId);
        var tokenFingerprint = CreateTokenFingerprint(request.BootstrapToken);

        logger.LogInformation(
            "Provisioning attempt for {device_id} with bootstrap token fingerprint {bootstrap_token_fingerprint}",
            safeDeviceId,
            tokenFingerprint);

        if (!certificateSigningRequestValidator.TryValidate(request.Csr, out var certificateRequest))
        {
            logger.LogWarning(
                "Provisioning rejected for {device_id} with fingerprint {bootstrap_token_fingerprint}: invalid CSR",
                safeDeviceId,
                tokenFingerprint);

            return Rejected(StatusCodes.Status400BadRequest);
        }

        var authorizationStatus = await authorizedDeviceRepository.TryBeginProvisioningAsync(
            normalizedDeviceId,
            request.BootstrapToken,
            cancellationToken);

        if (authorizationStatus == ProvisioningAuthorizationStatus.UnknownDeviceOrTokenMismatch)
        {
            logger.LogWarning(
                "Provisioning rejected for {device_id} with fingerprint {bootstrap_token_fingerprint}: unauthorized device or bootstrap token mismatch",
                safeDeviceId,
                tokenFingerprint);

            return Rejected(StatusCodes.Status403Forbidden);
        }

        if (authorizationStatus == ProvisioningAuthorizationStatus.AlreadyProvisioned)
        {
            logger.LogWarning(
                "Provisioning rejected for {device_id} with fingerprint {bootstrap_token_fingerprint}: bootstrap token already used",
                safeDeviceId,
                tokenFingerprint);

            return Rejected(StatusCodes.Status409Conflict);
        }

        string deviceCertificate;
        try
        {
            deviceCertificate = deviceCertificateSigner.SignDeviceCertificate(normalizedDeviceId, certificateRequest);
        }
        catch (CryptographicException)
        {
            await authorizedDeviceRepository.ResetProvisioningAsync(normalizedDeviceId, cancellationToken);

            logger.LogWarning(
                "Provisioning rejected for {device_id} with fingerprint {bootstrap_token_fingerprint}: invalid CSR",
                safeDeviceId,
                tokenFingerprint);

            return Rejected(StatusCodes.Status400BadRequest);
        }
        catch (InvalidOperationException)
        {
            await authorizedDeviceRepository.ResetProvisioningAsync(normalizedDeviceId, cancellationToken);

            logger.LogWarning(
                "Provisioning rejected for {device_id} with fingerprint {bootstrap_token_fingerprint}: CSR identity mismatch",
                safeDeviceId,
                tokenFingerprint);

            return Rejected(StatusCodes.Status400BadRequest);
        }

        logger.LogInformation(
            "Provisioning succeeded for {device_id} with bootstrap token fingerprint {bootstrap_token_fingerprint}",
            safeDeviceId,
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

    private static string CreateTokenFingerprint(string token)
    {
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(token)));
        return hash[..12];
    }

    private static string SanitizeForLog(string value) =>
        value
            .Replace("\r", string.Empty, StringComparison.Ordinal)
            .Replace("\n", string.Empty, StringComparison.Ordinal);
}
