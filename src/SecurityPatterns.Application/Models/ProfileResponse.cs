namespace SecurityPatterns.Application.Models;

/// <summary>
/// Represents the authenticated user's profile extracted from the JWT token.
/// </summary>
public sealed record ProfileResponse
{
    public required string Username { get; init; }
    public required bool IsAuthenticated { get; init; }
    public required IDictionary<string, string> Claims { get; init; }
}
