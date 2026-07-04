using SecurityPatterns.Application.Interfaces;
using SecurityPatterns.Application.Models;
using SecurityPatterns.Core.Abstractions;

namespace SecurityPatterns.Application.Services;

/// <summary>
/// Orchestrates authentication use cases by delegating token operations
/// to the Core abstractions and mapping between application DTOs and domain types.
/// </summary>
public sealed class AuthService : IAuthService
{
    private readonly ITokenIssuer _tokenIssuer;
    private readonly TimeSpan _tokenLifetime;

    public AuthService(ITokenIssuer tokenIssuer, TimeSpan tokenLifetime)
    {
        _tokenIssuer = tokenIssuer;
        _tokenLifetime = tokenLifetime;
    }

    /// <inheritdoc />
    public TokenResponse? Authenticate(LoginRequest request)
    {
        DemoUsers.DemoUser? user = DemoUsers.Validate(request.Username, request.Password);

        if (user is null)
        {
            return null;
        }

        var claims = new Dictionary<string, string>
        {
            ["role"] = user.Role,
            ["scope"] = user.Scope
        };

        TokenResult result = _tokenIssuer.GenerateToken(
            user.SubjectId,
            user.Username,
            claims,
            _tokenLifetime);

        return new TokenResponse
        {
            Token = result.Token,
            ExpiresAt = result.ExpiresAt,
            TokenType = "Bearer"
        };
    }

    /// <inheritdoc />
    public ProfileResponse GetProfile(IDictionary<string, string> claims)
    {
        string username = claims.TryGetValue("unique_name", out string? name) ? name : "unknown";
        string role = claims.TryGetValue("role", out string? r) ? r : "none";

        return new ProfileResponse
        {
            Username = username,
            IsAuthenticated = true,
            Claims = claims
        };
    }
}
