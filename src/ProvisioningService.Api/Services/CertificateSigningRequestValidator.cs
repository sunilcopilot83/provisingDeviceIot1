using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace ProvisioningService.Api.Services;

public class CertificateSigningRequestValidator : ICertificateSigningRequestValidator
{
    private static readonly HashAlgorithmName[] SupportedHashAlgorithms =
    [
        HashAlgorithmName.SHA256,
        HashAlgorithmName.SHA384,
        HashAlgorithmName.SHA512,
    ];

    private static readonly RSASignaturePadding[] SupportedPaddings =
    [
        RSASignaturePadding.Pkcs1,
        RSASignaturePadding.Pss,
    ];

    public bool TryValidate(string? csrPem, out CertificateRequest certificateRequest)
    {
        certificateRequest = null!;

        if (string.IsNullOrWhiteSpace(csrPem))
        {
            return false;
        }

        var normalizedPem = csrPem.Trim();
        if (!normalizedPem.StartsWith("-----BEGIN CERTIFICATE REQUEST-----", StringComparison.Ordinal) ||
            !normalizedPem.EndsWith("-----END CERTIFICATE REQUEST-----", StringComparison.Ordinal))
        {
            return false;
        }

        foreach (var hashAlgorithm in SupportedHashAlgorithms)
        {
            foreach (var signaturePadding in SupportedPaddings)
            {
                try
                {
                    var parsedRequest = CertificateRequest.LoadSigningRequestPem(
                        normalizedPem,
                        hashAlgorithm,
                        CertificateRequestLoadOptions.Default,
                        signaturePadding);

                    if (parsedRequest.CertificateExtensions.OfType<X509BasicConstraintsExtension>().Any(extension => extension.CertificateAuthority))
                    {
                        return false;
                    }

                    certificateRequest = parsedRequest;
                    return true;
                }
                catch (ArgumentException)
                {
                }
                catch (CryptographicException)
                {
                }
            }
        }

        return false;
    }
}
