using System.Security.Cryptography.X509Certificates;

namespace ProvisioningService.Api.Services;

public interface ICertificateSigningRequestValidator
{
    bool TryValidate(string? csrPem, out CertificateRequest certificateRequest);
}
