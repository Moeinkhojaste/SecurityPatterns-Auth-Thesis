using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using SecurityPatterns.Application.Interfaces;
using SecurityPatterns.Application.Services;
using SecurityPatterns.Core.Abstractions;
using SecurityPatterns.VerifiableToken.Implementations;

var builder = WebApplication.CreateBuilder(args);

// ─── Configuration ────────────────────────────────────────────────────────
string secretKey = builder.Configuration["Jwt:SecretKey"]
    ?? throw new InvalidOperationException("Jwt:SecretKey is not configured.");
string issuer = builder.Configuration["Jwt:Issuer"]
    ?? throw new InvalidOperationException("Jwt:Issuer is not configured.");
string audience = builder.Configuration["Jwt:Audience"]
    ?? throw new InvalidOperationException("Jwt:Audience is not configured.");

int expiryMinutes = int.TryParse(builder.Configuration["Jwt:ExpiryMinutes"], out int m) ? m : 30;

// ─── Dependency Injection (Composition Root) ──────────────────────────────
// Register Core abstractions with their Infrastructure implementations.
builder.Services.AddSingleton<ITokenIssuer>(new JwtTokenIssuer(secretKey, issuer, audience));
builder.Services.AddSingleton<ITokenVerifier>(new JwtTokenVerifier(secretKey, issuer, audience));

// Register Application service
builder.Services.AddScoped<IAuthService>(sp =>
{
    ITokenIssuer issuer = sp.GetRequiredService<ITokenIssuer>();
    return new AuthService(issuer, TimeSpan.FromMinutes(expiryMinutes));
});

// ─── Authentication (JWT Bearer) ────────────────────────────────────────
byte[] keyBytes = Convert.FromBase64String(secretKey);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    // Disable claim mapping so raw JWT claim names (sub, unique_name, jti, etc.)
    // are preserved, matching the behaviour of JwtTokenVerifier.MapInboundClaims = false.
    options.MapInboundClaims = false;

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(keyBytes),
        ValidateIssuer = true,
        ValidIssuer = issuer,
        ValidateAudience = true,
        ValidAudience = audience,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero,
    };
});

builder.Services.AddAuthorization();

// ─── Controllers ──────────────────────────────────────────────────────────
builder.Services.AddControllers();

// ─── Swagger (with JWT Bearer support) ────────────────────────────────────
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "SecurityPatterns API",
        Version = "v1",
        Description = "ASP.NET Core Web API demonstrating Verifiable Token-based Authentication patterns."
    });

    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter your JWT token"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

// ─── Build ────────────────────────────────────────────────────────────────
var app = builder.Build();

// ─── Middleware Pipeline ──────────────────────────────────────────────────
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "SecurityPatterns API v1");
    });
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

app.Run();
