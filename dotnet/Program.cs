// Example: generating an AdvaView launch token in .NET (C#).
//
// An AdvaView launch token is a short-lived credential that grants a named user access to a
// specific set of studies in AdvaView, the AdvaPACS viewer. Your system builds the token, protects
// it with the access key you were issued, and passes it to AdvaView.
//
// How a launch token is produced:
//   1. Collect the inputs   - who the user is, which studies they may open, and the token lifetime.
//   2. Build the payload    - the JSON claims AdvaView will read.
//   3. Protect the payload  - encrypt it (JWE, recommended) or sign it (JWS) using your access key.
//
// Uses the jose-jwt library (https://github.com/dvsekhvalnov/jose-jwt).
//
// Usage:
//   dotnet run -- --username jane.doe@example.com --suid 1.2.840.113619.2.55.3.1234 \
//       --accessKeyId <id> --accessKeySecret <secret> --expireAfter 300

using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Jose;

try
{
    // Step 1: read and validate the inputs.
    var inputs = Inputs.Parse(args);

    // Step 2: build the JSON payload (the token's claims).
    string payload = TokenPayload.Build(inputs);

    if (inputs.Mode == "json")
    {
        // Debug output only: this payload is NOT protected and must not be used as a token.
        Console.WriteLine(payload);
        return 0;
    }

    // Step 3: protect the payload with the access key.
    byte[] key = TokenProtector.DeriveKey(inputs.AccessKeySecret!);
    string token = inputs.Mode == "jwe"
        ? TokenProtector.Encrypt(payload, inputs.AccessKeyId!, key) // recommended
        : TokenProtector.Sign(payload, inputs.AccessKeyId!, key);

    Console.WriteLine(token);
    return 0;
}
catch (Exception e)
{
    Console.Error.WriteLine($"Error: {e.Message}");
    Console.Error.WriteLine("""

        Usage:
          dotnet run -- \
            --username <username> \
            --expireAfter <seconds> \
            ( --suid <suid> [--suid <suid> ...] | --patientId <id> --accNum <acc> [--accNum <acc> ...] ) \
            --accessKeyId <id> \          # required unless --mode json
            --accessKeySecret <secret> \  # required unless --mode json
            [--mode jwe|jws|json]          # default: jwe
        """);
    return 1;
}

// ---------------------------------------------------------------------------------------------
// Step 1: the inputs needed to generate a token.
//
// In your own integration these values would come from your application: the signed-in user, the
// studies they are viewing, and the access key stored in your secrets manager.
// ---------------------------------------------------------------------------------------------
record Inputs(
    string Username,
    List<string> Suids,
    string? PatientId,
    List<string> AccNums,
    string Mode,
    string? AccessKeyId,
    string? AccessKeySecret,
    long ExpireAfter)
{
    public static Inputs Parse(string[] args)
    {
        string? username = null, patientId = null, accessKeyId = null, accessKeySecret = null;
        string mode = "jwe"; // JWE (encrypted) is the recommended default
        long? expireAfter = null;
        var suids = new List<string>();
        var accNums = new List<string>();

        for (int i = 0; i < args.Length; i++)
        {
            string name = args[i];
            if (i + 1 >= args.Length) throw new ArgumentException($"Missing value for {name}");
            string value = args[++i];

            switch (name)
            {
                case "--username": username = value; break;
                case "--suid": suids.Add(value); break;       // may be repeated
                case "--patientId": patientId = value; break;
                case "--accNum": accNums.Add(value); break;   // may be repeated
                case "--mode": mode = value.ToLowerInvariant(); break;
                case "--accessKeyId": accessKeyId = value; break;
                case "--accessKeySecret": accessKeySecret = value; break;
                case "--expireAfter": expireAfter = long.Parse(value); break;
                default: throw new ArgumentException($"Unknown argument: {name}");
            }
        }

        if (string.IsNullOrEmpty(username)) throw new ArgumentException("--username is required");
        if (expireAfter is null or <= 0)
            throw new ArgumentException("--expireAfter is required and must be a positive number of seconds");

        // Studies are identified EITHER by Study Instance UID, OR by patient ID + accession number(s).
        bool bySuid = suids.Count > 0;
        bool byAccession = !string.IsNullOrEmpty(patientId) && accNums.Count > 0;
        if (bySuid == byAccession)
            throw new ArgumentException(
                "Provide either at least one --suid, OR --patientId with at least one --accNum (not both)");

        if (mode is not ("jwe" or "jws" or "json"))
            throw new ArgumentException("--mode must be jwe, jws or json");
        if (mode != "json" && (string.IsNullOrEmpty(accessKeyId) || string.IsNullOrEmpty(accessKeySecret)))
            throw new ArgumentException("--accessKeyId and --accessKeySecret are required unless --mode is json");

        return new Inputs(username, suids, patientId, accNums, mode, accessKeyId, accessKeySecret, expireAfter.Value);
    }
}

// ---------------------------------------------------------------------------------------------
// Step 2: the JSON payload (the token's claims).
// ---------------------------------------------------------------------------------------------

/// <summary>Identifies one study, by EITHER its Study Instance UID OR its accession number.</summary>
record Study(
    [property: JsonPropertyName("studyInstanceUid")] string? StudyInstanceUid = null,
    [property: JsonPropertyName("accessionNumber")] string? AccessionNumber = null);

record TokenPayload(
    // The user the token is issued to.
    [property: JsonPropertyName("username")] string Username,
    // Only present when studies are identified by accession number.
    [property: JsonPropertyName("patientId")] string? PatientId,
    // The studies the user may open.
    [property: JsonPropertyName("studies")] List<Study> Studies,
    // When the token stops being accepted, in seconds since the Unix epoch (UTC).
    [property: JsonPropertyName("expiresAt")] long ExpiresAt,
    // A unique ID for this token. Generate a new random value for every token; it lets AdvaPACS
    // reject a token that is presented more than once.
    [property: JsonPropertyName("jti")] string Jti)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull, // omit unused fields
    };

    public static string Build(Inputs inputs)
    {
        bool bySuid = inputs.Suids.Count > 0;

        var studies = bySuid
            ? inputs.Suids.Select(uid => new Study(StudyInstanceUid: uid)).ToList()
            : inputs.AccNums.Select(acc => new Study(AccessionNumber: acc)).ToList();

        var payload = new TokenPayload(
            Username: inputs.Username,
            PatientId: bySuid ? null : inputs.PatientId,
            Studies: studies,
            ExpiresAt: DateTimeOffset.UtcNow.AddSeconds(inputs.ExpireAfter).ToUnixTimeSeconds(),
            Jti: Guid.NewGuid().ToString());

        return JsonSerializer.Serialize(payload, JsonOptions);
    }
}

// ---------------------------------------------------------------------------------------------
// Step 3: protect the payload with your access key.
//
//   Key derivation: the 256-bit key is SHA-256(UTF-8 bytes of the access key secret).
//                   Use the hash, not the raw secret.
//   Key ID:         the access key ID goes in the `kid` header so AdvaPACS knows which key to use.
//   JWE (recommended): alg A256KW, enc A256GCM. The payload is encrypted, so patient
//                      identifiers (PHI) can't leak into server logs, proxies or browser
//                      history, and it can't be altered.
//   JWS:               alg HS256. Tamper-proof, but the payload is only base64url-encoded,
//                      so anyone who sees the token can read it. Use only if you can't use JWE.
// ---------------------------------------------------------------------------------------------
static class TokenProtector
{
    public static byte[] DeriveKey(string accessKeySecret) =>
        SHA256.HashData(Encoding.UTF8.GetBytes(accessKeySecret));

    public static string Sign(string payload, string accessKeyId, byte[] key) =>
        JWT.Encode(
            payload,
            key,
            JwsAlgorithm.HS256,
            extraHeaders: new Dictionary<string, object> { ["kid"] = accessKeyId });

    public static string Encrypt(string payload, string accessKeyId, byte[] key) =>
        JWT.Encode(
            payload,
            key,
            JweAlgorithm.A256KW,
            JweEncryption.A256GCM,
            extraHeaders: new Dictionary<string, object> { ["kid"] = accessKeyId });
}
