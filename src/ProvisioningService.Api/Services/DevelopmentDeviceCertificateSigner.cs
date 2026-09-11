using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace ProvisioningService.Api.Services;

public class DevelopmentDeviceCertificateSigner : IDeviceCertificateSigner, IDisposable
{
    private readonly X509Certificate2 _certificateAuthorityCertificate;
    private readonly RSA _certificateAuthorityKey = RSA.Create(3072);

    public DevelopmentDeviceCertificateSigner()
    {
        var authorityRequest = new CertificateRequest(
            "CN=ProvisioningService Dev CA",
            _certificateAuthorityKey,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        authorityRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        authorityRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
        authorityRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(authorityRequest.PublicKey, false));

        _certificateAuthorityCertificate = authorityRequest.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(5));
    }

    public string SignDeviceCertificate(string deviceId, CertificateRequest certificateSigningRequest)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(deviceId);
        ArgumentNullException.ThrowIfNull(certificateSigningRequest);

        EnsureCertificateIdentityMatchesDevice(deviceId, certificateSigningRequest);
        EnsureRequestedExtensionsAreSafe(certificateSigningRequest);
        EnsureDeviceCertificateExtensions(certificateSigningRequest);

        using var certificate = certificateSigningRequest.Create(
            _certificateAuthorityCertificate.SubjectName,
            X509SignatureGenerator.CreateForRSA(_certificateAuthorityKey, RSASignaturePadding.Pkcs1),
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1),
            RandomNumberGenerator.GetBytes(16));

        return certificate.ExportCertificatePem();
    }

    public void Dispose()
    {
        _certificateAuthorityCertificate.Dispose();
        _certificateAuthorityKey.Dispose();
    }

    private static void EnsureCertificateIdentityMatchesDevice(string deviceId, CertificateRequest certificateSigningRequest)
    {
        var normalizedDeviceId = deviceId.Trim().ToUpperInvariant();
        var hyphenatedDeviceId = normalizedDeviceId.Replace(':', '-');
        var subject = certificateSigningRequest.SubjectName.Name ?? string.Empty;

        if (ContainsDeviceIdentity(subject, normalizedDeviceId, hyphenatedDeviceId))
        {
            return;
        }

        foreach (var extension in certificateSigningRequest.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>())
        {
            if (ContainsDeviceIdentity(extension.Format(false), normalizedDeviceId, hyphenatedDeviceId))
            {
                return;
            }
        }

        throw new InvalidOperationException("CSR identity does not match the requested device.");
    }

    private static void EnsureRequestedExtensionsAreSafe(CertificateRequest certificateSigningRequest)
    {
        foreach (var extension in certificateSigningRequest.CertificateExtensions)
        {
            switch (extension)
            {
                case X509BasicConstraintsExtension basicConstraintsExtension when basicConstraintsExtension.CertificateAuthority:
                    throw new InvalidOperationException("CSR requested CA privileges.");
                case X509KeyUsageExtension keyUsageExtension:
                    const X509KeyUsageFlags allowedKeyUsages =
                        X509KeyUsageFlags.DigitalSignature |
                        X509KeyUsageFlags.KeyEncipherment |
                        X509KeyUsageFlags.KeyAgreement;

                    if ((keyUsageExtension.KeyUsages & ~allowedKeyUsages) != 0)
                    {
                        throw new InvalidOperationException("CSR requested unsupported key usages.");
                    }

                    break;
                case X509EnhancedKeyUsageExtension enhancedKeyUsageExtension:
                    var ekuOids = enhancedKeyUsageExtension.EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.Value).ToArray();
                    if (ekuOids.Any(oid => oid != "1.3.6.1.5.5.7.3.2"))
                    {
                        throw new InvalidOperationException("CSR requested unsupported enhanced key usages.");
                    }

                    break;
            }
        }
    }

    private static void EnsureDeviceCertificateExtensions(CertificateRequest certificateSigningRequest)
    {
        var basicConstraintsExtension = certificateSigningRequest.CertificateExtensions.OfType<X509BasicConstraintsExtension>().SingleOrDefault();
        if (basicConstraintsExtension is null)
        {
            certificateSigningRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        }
        else if (basicConstraintsExtension.CertificateAuthority)
        {
            throw new InvalidOperationException("CSR requested CA privileges.");
        }

        var keyUsageExtension = certificateSigningRequest.CertificateExtensions.OfType<X509KeyUsageExtension>().SingleOrDefault();
        if (keyUsageExtension is null)
        {
            certificateSigningRequest.CertificateExtensions.Add(
                new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        }

        if (!certificateSigningRequest.CertificateExtensions.OfType<X509EnhancedKeyUsageExtension>().Any())
        {
            certificateSigningRequest.CertificateExtensions.Add(
                new X509EnhancedKeyUsageExtension(
                    new OidCollection
                    {
                        new("1.3.6.1.5.5.7.3.2", "Client Authentication"),
                    },
                    true));
        }

        if (!certificateSigningRequest.CertificateExtensions.OfType<X509SubjectKeyIdentifierExtension>().Any())
        {
            certificateSigningRequest.CertificateExtensions.Add(
                new X509SubjectKeyIdentifierExtension(certificateSigningRequest.PublicKey, false));
        }
    }

    private static bool ContainsDeviceIdentity(string candidate, string normalizedDeviceId, string hyphenatedDeviceId) =>
        Regex.IsMatch(
            candidate,
            $@"\b({Regex.Escape(normalizedDeviceId)}|{Regex.Escape(hyphenatedDeviceId)})\b",
            RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
}
