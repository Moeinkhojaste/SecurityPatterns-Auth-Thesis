namespace SecurityPatterns.Core.Abstractions;

/// <summary>
/// Represents the outcome of a successful token issuance operation.
/// </summary>
/// <remarks>
/// This record serves as an immutable data-transfer object returned by <see cref="ITokenIssuer.GenerateToken"/>.
/// Immutability is enforced by the <c>record</c> type, ensuring that token artifacts cannot be mutated
/// after issuance, which is critical for audit logging and replay-prevention mechanisms.
/// </remarks>
/// <param name="Token">
/// The serialized token string that the caller must present to protected resources.
/// The format (JWT, opaque reference, etc.) is determined by the concrete issuer implementation.
/// </param>
/// <param name="TokenId">
/// A unique, non-guessable identifier for the issued token.
/// This value is used as the key for token revocation, revocation-list lookups,
/// and correlation in distributed tracing contexts.
/// </param>
/// <param name="ExpiresAt">
/// The UTC date and time at which the token ceases to be valid.
/// Implementations MUST enforce this expiration at verification time to prevent
/// the use of expired credentials, mitigating token-reuse attacks.
/// </param>
public sealed record TokenResult(string Token, string TokenId, DateTime ExpiresAt);
