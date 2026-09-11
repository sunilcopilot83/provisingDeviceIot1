using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Logging;
using ProvisioningService.Api.Models;
using ProvisioningService.Api.Services;
using Xunit;

namespace ProvisioningService.Api.Tests;

public class ProvisioningEndpointTests
{
    [Fact]
    public async Task Valid_provisioning_request_returns_certificate_pem()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        const string deviceId = "AA:BB:CC:DD:EE:FF";
        const string bootstrapToken = "boot-token-123";

        await RegisterDeviceAsync(client, deviceId, bootstrapToken);

        var response = await client.PostAsync(
            "/api/v1/provision",
            ToJsonContent(new
            {
                device_id = deviceId,
                bootstrap_token = bootstrapToken,
                csr = CreateSigningRequestPem(deviceId),
            }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        using var jsonDocument = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var certificatePem = jsonDocument.RootElement.GetProperty("device_certificate").GetString();

        Assert.NotNull(certificatePem);
        Assert.StartsWith("-----BEGIN CERTIFICATE-----", certificatePem, StringComparison.Ordinal);
        Assert.EndsWith("-----END CERTIFICATE-----", certificatePem.Trim(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Unknown_device_or_mismatched_token_is_rejected()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        const string deviceId = "AA:BB:CC:DD:EE:FF";
        await RegisterDeviceAsync(client, deviceId, "expected-token");

        var response = await client.PostAsync(
            "/api/v1/provision",
            ToJsonContent(new
            {
                device_id = deviceId,
                bootstrap_token = "wrong-token",
                csr = CreateSigningRequestPem(deviceId),
            }));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Contains("\"error\":\"provisioning request rejected\"", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Invalid_csr_is_rejected()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        const string deviceId = "AA:BB:CC:DD:EE:FF";
        const string bootstrapToken = "boot-token-123";

        await RegisterDeviceAsync(client, deviceId, bootstrapToken);

        var response = await client.PostAsync(
            "/api/v1/provision",
            ToJsonContent(new
            {
                device_id = deviceId,
                bootstrap_token = bootstrapToken,
                csr = "-----BEGIN CERTIFICATE REQUEST-----\nnot-a-valid-csr\n-----END CERTIFICATE REQUEST-----",
            }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("\"error\":\"provisioning request rejected\"", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Missing_required_fields_return_validation_errors()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        var response = await client.PostAsync("/api/v1/provision", ToJsonContent(new { }));
        var responseBody = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("\"errors\"", responseBody, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Camel_case_aliases_and_multiline_csr_bind_correctly()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        const string deviceId = "AA:BB:CC:DD:EE:FF";
        const string bootstrapToken = "boot-token-123";
        var csr = CreateEcdsaSigningRequestPem(deviceId);

        await RegisterDeviceAsync(client, deviceId, bootstrapToken);

        var response = await client.PostAsync(
            "/api/v1/provision",
            ToJsonContent(new
            {
                deviceId,
                bootstrapToken,
                csr,
            }));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Repeated_provisioning_attempt_is_rejected_with_conflict()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        const string deviceId = "AA:BB:CC:DD:EE:FF";
        const string bootstrapToken = "boot-token-123";
        var requestContent = ToJsonContent(new
        {
            device_id = deviceId,
            bootstrap_token = bootstrapToken,
            csr = CreateSigningRequestPem(deviceId),
        });

        await RegisterDeviceAsync(client, deviceId, bootstrapToken);

        var firstResponse = await client.PostAsync("/api/v1/provision", requestContent);
        firstResponse.EnsureSuccessStatusCode();

        var secondResponse = await client.PostAsync(
            "/api/v1/provision",
            ToJsonContent(new
            {
                device_id = deviceId,
                bootstrap_token = bootstrapToken,
                csr = CreateSigningRequestPem(deviceId),
            }));

        Assert.Equal(HttpStatusCode.Conflict, secondResponse.StatusCode);
        Assert.Contains("\"error\":\"provisioning request rejected\"", await secondResponse.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Csr_identity_mismatch_is_rejected()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        const string deviceId = "AA:BB:CC:DD:EE:FF";
        const string bootstrapToken = "boot-token-123";

        await RegisterDeviceAsync(client, deviceId, bootstrapToken);

        var response = await client.PostAsync(
            "/api/v1/provision",
            ToJsonContent(new
            {
                device_id = deviceId,
                bootstrap_token = bootstrapToken,
                csr = CreateSigningRequestPem("11:22:33:44:55:66"),
            }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("\"error\":\"provisioning request rejected\"", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Csr_requesting_ca_privileges_is_rejected()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        const string deviceId = "AA:BB:CC:DD:EE:FF";
        const string bootstrapToken = "boot-token-123";

        await RegisterDeviceAsync(client, deviceId, bootstrapToken);

        var response = await client.PostAsync(
            "/api/v1/provision",
            ToJsonContent(new
            {
                device_id = deviceId,
                bootstrap_token = bootstrapToken,
                csr = CreateCertificateAuthoritySigningRequestPem(deviceId),
            }));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Contains("\"error\":\"provisioning request rejected\"", await response.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Re_registering_a_provisioned_device_does_not_re_enable_provisioning()
    {
        using var factory = new WebApplicationFactory<Program>();
        using var client = factory.CreateClient();

        const string deviceId = "AA:BB:CC:DD:EE:FF";
        const string bootstrapToken = "boot-token-123";

        await RegisterDeviceAsync(client, deviceId, bootstrapToken);

        var firstProvisionResponse = await client.PostAsync(
            "/api/v1/provision",
            ToJsonContent(new
            {
                device_id = deviceId,
                bootstrap_token = bootstrapToken,
                csr = CreateSigningRequestPem(deviceId),
            }));

        firstProvisionResponse.EnsureSuccessStatusCode();

        await RegisterDeviceAsync(client, deviceId, "updated-token");

        var secondProvisionResponse = await client.PostAsync(
            "/api/v1/provision",
            ToJsonContent(new
            {
                device_id = deviceId,
                bootstrap_token = "updated-token",
                csr = CreateSigningRequestPem(deviceId),
            }));

        Assert.Equal(HttpStatusCode.Conflict, secondProvisionResponse.StatusCode);
        Assert.Contains("\"error\":\"provisioning request rejected\"", await secondProvisionResponse.Content.ReadAsStringAsync(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Bootstrap_token_is_not_logged_in_plaintext()
    {
        var logger = new TestLogger<InMemoryProvisioningService>();
        var service = new InMemoryProvisioningService(
            new InMemoryAuthorizedDeviceRepository(),
            new CertificateSigningRequestValidator(),
            new DevelopmentDeviceCertificateSigner(),
            logger);

        const string deviceId = "AA:BB:CC:DD:EE:FF";
        const string bootstrapToken = "super-secret-bootstrap-token";

        await service.RegisterDeviceAsync(new ManufacturingDeviceRequest
        {
            DeviceId = deviceId,
            BootstrapToken = bootstrapToken,
        });

        var result = await service.ProvisionDeviceAsync(new ProvisioningRequest
        {
            DeviceId = deviceId,
            BootstrapToken = bootstrapToken,
            Csr = CreateSigningRequestPem(deviceId),
        });

        Assert.Equal(HttpStatusCode.OK, (HttpStatusCode)result.StatusCode);
        Assert.DoesNotContain(logger.Messages, message => message.Contains(bootstrapToken, StringComparison.Ordinal));
        Assert.Contains(logger.Messages, message => message.Contains("fingerprint", StringComparison.OrdinalIgnoreCase));
    }

    private static async Task RegisterDeviceAsync(HttpClient client, string deviceId, string bootstrapToken)
    {
        var response = await client.PostAsJsonAsync(
            "/api/v1/manufacturing/device",
            new ManufacturingDeviceRequest
            {
                DeviceId = deviceId,
                BootstrapToken = bootstrapToken,
            });

        response.EnsureSuccessStatusCode();
    }

    private static StringContent ToJsonContent<T>(T payload) =>
        new(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");

    private static string CreateSigningRequestPem(string deviceId)
    {
        using var key = RSA.Create(2048);
        var subject = $"CN=device-{deviceId.Replace(':', '-')}";
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSigningRequestPem();
    }

    private static string CreateEcdsaSigningRequestPem(string deviceId)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var subject = $"CN=device-{deviceId.Replace(':', '-')}";
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        return request.CreateSigningRequestPem();
    }

    private static string CreateCertificateAuthoritySigningRequestPem(string deviceId)
    {
        using var key = RSA.Create(2048);
        var subject = $"CN=device-{deviceId.Replace(':', '-')}";
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        return request.CreateSigningRequestPem();
    }

    private sealed class TestLogger<T> : ILogger<T>
    {
        public List<string> Messages { get; } = [];

        IDisposable? ILogger.BeginScope<TState>(TState state) => null;

        bool ILogger.IsEnabled(LogLevel logLevel) => true;

        void ILogger.Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            Messages.Add(formatter(state, exception));
        }
    }
}
