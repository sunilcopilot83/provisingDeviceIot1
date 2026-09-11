using System.Reflection;
using ProvisioningService.Api.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
    options.IncludeXmlComments(xmlPath, includeControllerXmlComments: true);
});
builder.Services.AddSingleton<IAuthorizedDeviceRepository, InMemoryAuthorizedDeviceRepository>();
builder.Services.AddSingleton<ICertificateSigningRequestValidator, CertificateSigningRequestValidator>();
builder.Services.AddSingleton<IDeviceCertificateSigner, DevelopmentDeviceCertificateSigner>();
builder.Services.AddSingleton<IProvisioningService, InMemoryProvisioningService>();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();

public partial class Program;
