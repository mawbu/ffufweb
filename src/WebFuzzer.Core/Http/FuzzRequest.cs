using WebFuzzer.Core.Models;

namespace WebFuzzer.Core.Http;

/// <summary>
/// Model DTO đại diện cho một HTTP request fuzz đã được build sẵn.
/// Dùng để lưu thông tin request (cho test, logging, reporting).
/// KHÔNG dùng để gửi HTTP request thực tế — hãy dùng RequestBuilder.Build() thay thế.
/// </summary>
public class FuzzRequest
{
    /// <summary>HTTP method.</summary>
    public string Method { get; set; } = "GET";

    /// <summary>URL đầy đủ sau khi thay FUZZ (payload đã được URL-encoded).</summary>
    public string Url { get; set; } = string.Empty;

    /// <summary>Payload gốc (RAW, chưa encode) từ wordlist.</summary>
    public string Payload { get; set; } = string.Empty;

    /// <summary>Headers của request.</summary>
    public Dictionary<string, string> Headers { get; set; } = new();

    /// <summary>Body của request (POST/PUT) — payload KHÔNG encode, vì body thường là JSON/form.</summary>
    public string? Body { get; set; }

    /// <summary>
    /// Tạo FuzzRequest DTO từ FuzzOptions và payload cụ thể.
    /// URL-encode payload CHỈ khi inject vào URL query string.
    /// Header và Body KHÔNG encode để giữ nguyên ký tự đặc biệt (JSON, form data).
    /// </summary>
    public static FuzzRequest Build(FuzzOptions options, string payload)
    {
        // Chỉ URL-encode khi FUZZ nằm trong URL — không encode khi ở header/body
        var encodedPayload = options.Url.Contains("FUZZ") ? Uri.EscapeDataString(payload) : payload;

        var req = new FuzzRequest
        {
            Method  = options.Method.ToUpperInvariant(),
            Url     = options.Url.Replace("FUZZ", encodedPayload),
            Payload = payload,  // lưu payload gốc, chưa encode
            Body    = options.Data?.Replace("FUZZ", payload)  // body: payload raw (không encode)
        };

        // Parse custom headers — KHÔNG encode payload trong header
        foreach (var header in options.Headers ?? [])
        {
            var idx = header.IndexOf(':');
            if (idx > 0)
            {
                var name  = header[..idx].Trim();
                var value = header[(idx + 1)..].Trim().Replace("FUZZ", payload);
                req.Headers[name] = value;
            }
        }

        // Cookie
        if (!string.IsNullOrWhiteSpace(options.Cookie))
            req.Headers["Cookie"] = options.Cookie;

        return req;
    }
}
