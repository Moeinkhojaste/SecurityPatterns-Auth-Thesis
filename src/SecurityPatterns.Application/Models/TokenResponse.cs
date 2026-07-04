namespace SecurityPatterns.Application.Models;

/// <summary>
/// Represents the outcome of a successful token issuance.
/// </summary>
public sealed record TokenResponse
{
    public required string Token { get; init; }
    public required DateTime ExpiresAt { get; init; }
    public required string TokenType { get; init; } = "Bearer";
}
