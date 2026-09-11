using System.Security.Cryptography.X509Certificates;

namespace ProvisioningService.Api.Services;

public interface IDeviceCertificateSigner
{
    string SignDeviceCertificate(string deviceId, CertificateRequest certificateSigningRequest);
}
