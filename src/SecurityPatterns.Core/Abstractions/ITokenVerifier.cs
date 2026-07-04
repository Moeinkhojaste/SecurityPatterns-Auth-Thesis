namespace SecurityPatterns.Core.Abstractions;

/// <summary>
/// Defines the contract for a component that validates authentication tokens
/// and extracts their embedded claims.
/// </summary>
/// <remarks>
/// <para>
/// Separating verification from issuance (Single Responsibility Principle) ensures that
/// each concern can evolve independently — a verifier may validate tokens produced by
/// external issuers (e.g., third-party identity providers) without coupling to the
/// issuance mechanism.
/// </para>
/// <para>
/// Security considerations:
/// <list type="bullet">
///   <item>Implementations MUST reject expired tokens, tokens with invalid signatures,
///         and tokens whose issuer or audience claims do not match expected values.</item>
///   <item>The <c>out</c> parameter <paramref name="extractedClaims"/> MUST contain only
///         claims that have been cryptographically verified. Unverified or tampered claims
///         MUST NOT be surfaced to callers.</item>
///   <item>Implementations SHOULD be stateless where possible to support horizontal scaling
///         and to avoid shared mutable state that could be exploited in race conditions.</item>
/// </list>
/// </para>
/// </remarks>
public interface ITokenVerifier
{
    /// <summary>
    /// Validates the integrity, authenticity, and temporal validity of the given token.
    /// </summary>
    /// <param name="token">
    /// The serialized token string to validate. MUST NOT be <see langword="null"/> or empty.
    /// </param>
    /// <param name="extractedClaims">
    /// When this method returns <see langword="true"/>, contains the claims extracted from
    /// the validated token. When the token is invalid or expired, this parameter is
    /// <see langword="null"/>.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the token is valid, unexpired, and its signature/integrity
    /// is verified; otherwise, <see langword="false"/>.
    /// </returns>
    bool ValidateToken(string token, out IDictionary<string, string>? extractedClaims);
}
