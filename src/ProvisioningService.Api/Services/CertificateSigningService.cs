using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ProvisioningService.Api.Services;

public interface ICertificateSigningService
{
    string SignDeviceCertificate(string deviceId, CertificateRequest certificateRequest, CancellationToken cancellationToken = default);
}

public sealed class FileBackedCertificateSigningService : ICertificateSigningService, IDisposable
{
    private readonly X509Certificate2 _issuerCertificate;
    private readonly ILogger<FileBackedCertificateSigningService> _logger;

    public FileBackedCertificateSigningService(
        IConfiguration configuration,
        IHostEnvironment hostEnvironment,
        ILogger<FileBackedCertificateSigningService> logger)
    {
        _logger = logger;
        var issuerPath = configuration["Provisioning:IssuerCertificatePath"];
        var issuerPassword = configuration["Provisioning:IssuerCertificatePassword"] ?? string.Empty;

        _issuerCertificate = LoadOrCreateIssuerCertificate(
            issuerPath ?? Path.Combine(AppContext.BaseDirectory, "provisioning-issuer.pfx"),
            issuerPassword,
            hostEnvironment.IsDevelopment(),
            configuration["Provisioning:IssuerCertificatePath"] is null);
    }

    public string SignDeviceCertificate(string deviceId, CertificateRequest certificateRequest, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (string.IsNullOrWhiteSpace(deviceId))
        {
            throw new ArgumentException("Device identifier is required.", nameof(deviceId));
        }

        EnsureExtension(
            certificateRequest,
            "2.5.29.19",
            () => new X509BasicConstraintsExtension(false, false, 0, true));
        EnsureExtension(
            certificateRequest,
            "2.5.29.15",
            () => new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                critical: true));
        EnsureExtension(
            certificateRequest,
            "2.5.29.14",
            () => new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

        var subjectAlternativeNameBuilder = new SubjectAlternativeNameBuilder();
        subjectAlternativeNameBuilder.AddUri(new Uri($"urn:jarvis-device:{Uri.EscapeDataString(deviceId)}"));
        EnsureExtension(certificateRequest, "2.5.29.17", () => subjectAlternativeNameBuilder.Build());

        var serialNumber = RandomNumberGenerator.GetBytes(16);
        serialNumber[0] &= 0x7F;
        if (serialNumber.All(static value => value == 0))
        {
            serialNumber[^1] = 1;
        }

        var issuedCertificate = certificateRequest.Create(
            _issuerCertificate,
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1),
            serialNumber);

        return PemEncoding.WriteString("CERTIFICATE", issuedCertificate.Export(X509ContentType.Cert));
    }

    private static void EnsureExtension(
        CertificateRequest certificateRequest,
        string oidValue,
        Func<X509Extension> extensionFactory)
    {
        if (certificateRequest.CertificateExtensions.OfType<X509Extension>().Any(extension => extension.Oid?.Value == oidValue))
        {
            return;
        }

        certificateRequest.CertificateExtensions.Add(extensionFactory());
    }

    private X509Certificate2 LoadOrCreateIssuerCertificate(
        string issuerPath,
        string issuerPassword,
        bool isDevelopment,
        bool usingDefaultPath)
    {
        if (File.Exists(issuerPath))
        {
            return X509CertificateLoader.LoadPkcs12FromFile(
                issuerPath,
                issuerPassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet,
                Pkcs12LoaderLimits.Defaults);
        }

        if (!isDevelopment)
        {
            throw new InvalidOperationException(
                "Provisioning issuer certificate not found. Configure Provisioning:IssuerCertificatePath and Provisioning:IssuerCertificatePassword before starting the service.");
        }

        var issuerDirectory = Path.GetDirectoryName(issuerPath);
        if (!string.IsNullOrWhiteSpace(issuerDirectory))
        {
            Directory.CreateDirectory(issuerDirectory);
        }

        using var issuerKey = RSA.Create(3072);
        var issuerRequest = new CertificateRequest(
            "CN=Jarvis Provisioning Test CA",
            issuerKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        issuerRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(issuerRequest.PublicKey, false));

        using var generatedIssuerCertificate = issuerRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(10));

        File.WriteAllBytes(issuerPath, generatedIssuerCertificate.Export(X509ContentType.Pfx, issuerPassword));
        _logger.LogWarning(
            usingDefaultPath
                ? "Provisioning issuer certificate not configured; generated development issuer certificate at default path {IssuerPath}"
                : "Provisioning issuer certificate not found; generated development issuer certificate at configured path {IssuerPath}",
            issuerPath);

        return X509CertificateLoader.LoadPkcs12FromFile(
            issuerPath,
            issuerPassword,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet,
            Pkcs12LoaderLimits.Defaults);
    }

    public void Dispose()
    {
        _issuerCertificate.Dispose();
    }
}
