using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ProvisioningService.Api.Services;

public interface ICertificateSigningService
{
    string SignDeviceCertificate(string deviceId, CertificateRequest certificateRequest, CancellationToken cancellationToken = default);
}

public sealed class EphemeralCertificateSigningService : ICertificateSigningService, IDisposable
{
    private readonly RSA _issuerKey = RSA.Create(3072);
    private readonly X509Certificate2 _issuerCertificate;

    public EphemeralCertificateSigningService()
    {
        var issuerRequest = new CertificateRequest(
            "CN=Jarvis Provisioning Test CA",
            _issuerKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        issuerRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        issuerRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(issuerRequest.PublicKey, false));

        _issuerCertificate = issuerRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(10));
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
        var issuedCertificate = certificateRequest.Create(
            _issuerCertificate.SubjectName,
            X509SignatureGenerator.CreateForRSA(_issuerKey, RSASignaturePadding.Pkcs1),
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

    public void Dispose()
    {
        _issuerCertificate.Dispose();
        _issuerKey.Dispose();
    }
}
