using System.Collections.Concurrent;
using System.Formats.Asn1;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Text;
using ProvisioningService.Api.Models;

namespace ProvisioningService.Api.Services;

public partial class InMemoryProvisioningService(
    ICertificateSigningService certificateSigningService,
    ILogger<InMemoryProvisioningService> logger) : IProvisioningService
{
    private const string GenericRejection = "provisioning request rejected";
    private const string InvalidDeviceIdError = "invalid device_id";
    private const string InvalidBootstrapTokenError = "invalid bootstrap_token";
    private const string InvalidCsrError = "invalid csr";
    private const string DeviceAlreadyProvisionedError = "device already provisioned";
    private const string ProvisioningInProgressError = "device provisioning already in progress";

    private readonly ConcurrentDictionary<string, DeviceRecord> _deviceRecords = new();

    public Task<ManufacturingDeviceResponse> RegisterDeviceAsync(ManufacturingDeviceRequest request, CancellationToken cancellationToken = default)
    {
        var normalizedDeviceId = NormalizeDeviceId(request.DeviceId);
        var normalizedBootstrapToken = NormalizeBootstrapToken(request.BootstrapToken);

        _deviceRecords[normalizedDeviceId] = new DeviceRecord
        {
            BootstrapTokenHash = HashToken(normalizedBootstrapToken),
            Used = false,
        };

        logger.LogInformation(
            "Registered provisioning record for device {DeviceId} with token fingerprint {TokenFingerprint}",
            normalizedDeviceId,
            GetTokenFingerprint(normalizedBootstrapToken));

        return Task.FromResult(new ManufacturingDeviceResponse
        {
            Status = "registered",
            DeviceId = normalizedDeviceId,
        });
    }

    public Task<ProvisioningResult> ProvisionDeviceAsync(ProvisioningRequest request, CancellationToken cancellationToken = default)
    {
        var rawDeviceId = request.DeviceId ?? string.Empty;
        var rawBootstrapToken = request.BootstrapToken ?? string.Empty;
        var normalizedDeviceId = NormalizeDeviceId(rawDeviceId);

        logger.LogInformation(
            "Provisioning attempt received for device {DeviceId}",
            normalizedDeviceId);

        if (!IsValidDeviceId(normalizedDeviceId))
        {
            logger.LogWarning("Provisioning rejected for device {DeviceId}: invalid device identifier format", normalizedDeviceId);
            return Task.FromResult(Rejected((int)HttpStatusCode.BadRequest, InvalidDeviceIdError));
        }

        var normalizedBootstrapToken = NormalizeBootstrapToken(rawBootstrapToken);

        if (!IsValidBootstrapToken(normalizedBootstrapToken))
        {
            logger.LogWarning(
                "Provisioning rejected for device {DeviceId}: invalid bootstrap token format",
                normalizedDeviceId);
            return Task.FromResult(Rejected((int)HttpStatusCode.BadRequest, InvalidBootstrapTokenError));
        }

        var tokenFingerprint = GetTokenFingerprint(normalizedBootstrapToken);

        if (!_deviceRecords.TryGetValue(normalizedDeviceId, out var record))
        {
            logger.LogWarning(
                "Provisioning rejected for device {DeviceId}: no authorized provisioning record matched fingerprint {TokenFingerprint}",
                normalizedDeviceId,
                tokenFingerprint);
            return Task.FromResult(Rejected((int)HttpStatusCode.Forbidden));
        }

        CertificateRequest csr;

        try
        {
            csr = ParseCsr(request.Csr);
        }
        catch (CryptographicException exception)
        {
            logger.LogWarning(
                exception,
                "Provisioning rejected for device {DeviceId}: CSR parsing failed",
                normalizedDeviceId);
            return Task.FromResult(Rejected((int)HttpStatusCode.BadRequest, InvalidCsrError));
        }

        lock (record.SyncRoot)
        {
            if (record.Used)
            {
                logger.LogWarning("Provisioning rejected for device {DeviceId}: device already provisioned", normalizedDeviceId);
                return Task.FromResult(Rejected((int)HttpStatusCode.Conflict, DeviceAlreadyProvisionedError));
            }

            if (record.ProvisioningInProgress)
            {
                logger.LogWarning("Provisioning rejected for device {DeviceId}: provisioning already in progress", normalizedDeviceId);
                return Task.FromResult(Rejected((int)HttpStatusCode.Conflict, ProvisioningInProgressError));
            }

            if (!TokenMatches(record.BootstrapTokenHash, normalizedBootstrapToken))
            {
                logger.LogWarning(
                    "Provisioning rejected for device {DeviceId}: bootstrap token mismatch for fingerprint {TokenFingerprint}",
                    normalizedDeviceId,
                    tokenFingerprint);
                return Task.FromResult(Rejected((int)HttpStatusCode.Forbidden));
            }

            record.ProvisioningInProgress = true;
        }

        string certificatePem;

        try
        {
            certificatePem = certificateSigningService.SignDeviceCertificate(normalizedDeviceId, csr, cancellationToken);
        }
        catch (Exception exception)
        {
            lock (record.SyncRoot)
            {
                record.ProvisioningInProgress = false;
            }

            logger.LogError(exception, "Provisioning failed for device {DeviceId}: certificate signing failed", normalizedDeviceId);
            return Task.FromResult(Rejected((int)HttpStatusCode.InternalServerError));
        }

        lock (record.SyncRoot)
        {
            record.ProvisioningInProgress = false;
            record.Used = true;
        }

        logger.LogInformation("Provisioning succeeded for device {DeviceId}", normalizedDeviceId);

        return Task.FromResult(new ProvisioningResult
        {
            StatusCode = (int)HttpStatusCode.OK,
            Response = new ProvisioningResponse
            {
                DeviceCertificate = certificatePem,
            },
        });
    }

    private static ProvisioningResult Rejected(int statusCode, string? error = null) => new()
    {
        StatusCode = statusCode,
        Error = error ?? GenericRejection,
    };

    private static string NormalizeDeviceId(string deviceId) =>
        deviceId.Trim().Replace('-', ':').ToUpperInvariant();

    private static string NormalizeBootstrapToken(string token) => token.Trim().ToUpperInvariant();

    private static bool IsValidDeviceId(string deviceId) => DeviceIdPattern().IsMatch(deviceId);

    private static bool IsValidBootstrapToken(string token) => BootstrapTokenPattern().IsMatch(token);

    private static CertificateRequest ParseCsr(string csrPem)
    {
        if (string.IsNullOrWhiteSpace(csrPem))
        {
            throw new CryptographicException("CSR payload is empty.");
        }

        var normalizedPem = csrPem.Trim();
        var (hashAlgorithm, padding) = ResolveSignatureParameters(normalizedPem);
        var certificateRequest = CertificateRequest.LoadSigningRequestPem(
            normalizedPem,
            hashAlgorithm,
            CertificateRequestLoadOptions.Default,
            padding);

        ValidatePublicKey(certificateRequest);
        return certificateRequest;
    }

    private static void ValidatePublicKey(CertificateRequest certificateRequest)
    {
        using var rsa = certificateRequest.PublicKey.GetRSAPublicKey();
        if (rsa is not null)
        {
            if (rsa.KeySize < 2048)
            {
                throw new CryptographicException("RSA public key is too small.");
            }

            return;
        }

        using var ecdsa = certificateRequest.PublicKey.GetECDsaPublicKey();
        if (ecdsa is not null)
        {
            if (ecdsa.KeySize < 256)
            {
                throw new CryptographicException("ECDSA public key is too small.");
            }

            return;
        }

        throw new CryptographicException("Unsupported CSR public key algorithm.");
    }

    private static byte[] HashToken(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));

    private static bool TokenMatches(byte[] expectedHash, string suppliedToken)
    {
        var suppliedHash = HashToken(suppliedToken);
        return CryptographicOperations.FixedTimeEquals(expectedHash, suppliedHash);
    }

    private static string GetTokenFingerprint(string token)
        => Convert.ToHexString(HashToken(token))[..12];

    private static (HashAlgorithmName HashAlgorithm, RSASignaturePadding? Padding) ResolveSignatureParameters(string csrPem)
    {
        if (!PemEncoding.TryFind(csrPem, out var fields))
        {
            throw new CryptographicException("CSR payload is not valid PEM.");
        }

        var label = csrPem[fields.Label];
        if (!string.Equals(label, "CERTIFICATE REQUEST", StringComparison.Ordinal) &&
            !string.Equals(label, "NEW CERTIFICATE REQUEST", StringComparison.Ordinal))
        {
            throw new CryptographicException("CSR PEM label is invalid.");
        }

        var csrDer = Convert.FromBase64String(csrPem[fields.Base64Data]);
        var reader = new AsnReader(csrDer, AsnEncodingRules.DER);
        var requestSequence = reader.ReadSequence();
        _ = requestSequence.ReadEncodedValue();

        var algorithmSequence = requestSequence.ReadSequence();
        var algorithmOid = algorithmSequence.ReadObjectIdentifier();

        return algorithmOid switch
        {
            "1.2.840.113549.1.1.11" => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            "1.2.840.113549.1.1.12" => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            "1.2.840.113549.1.1.13" => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
            "1.2.840.10045.4.3.2" => (HashAlgorithmName.SHA256, null),
            "1.2.840.10045.4.3.3" => (HashAlgorithmName.SHA384, null),
            "1.2.840.10045.4.3.4" => (HashAlgorithmName.SHA512, null),
            _ => throw new CryptographicException("CSR signature algorithm is not supported."),
        };
    }

    [GeneratedRegex("^([0-9A-F]{2}:){5}[0-9A-F]{2}$", RegexOptions.CultureInvariant)]
    private static partial Regex DeviceIdPattern();

    [GeneratedRegex("^[0-9A-F]{130}$", RegexOptions.CultureInvariant)]
    private static partial Regex BootstrapTokenPattern();

    private sealed class DeviceRecord
    {
        public byte[] BootstrapTokenHash { get; init; } = Array.Empty<byte>();

        public bool Used { get; set; }

        public bool ProvisioningInProgress { get; set; }

        public object SyncRoot { get; } = new();
    }
}
