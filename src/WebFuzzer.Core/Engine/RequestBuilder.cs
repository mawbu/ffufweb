using System.Text.RegularExpressions;
using WebFuzzer.Core.Models;

namespace WebFuzzer.Core.Engine;

public static class RequestBuilder
{
    // Regex phát hiện payload đã có percent-encoded sequence (%XX)
    // Ví dụ: %20, %27, %2A, %C0%80, etc.
    private static readonly Regex _percentEncodedPattern =
        new(@"%[0-9A-Fa-f]{2}", RegexOptions.Compiled);

    /// <summary>
    /// Kiểm tra xem payload có chứa chuỗi đã được percent-encode chưa.
    /// Nếu rồi → KHÔNG encode thêm lần nữa (tránh double encoding).
    /// Ví dụ: "%20or%201=1" → đã encode → skip
    ///        "' OR 1=1--"  → chưa encode → encode bình thường
    /// </summary>
    private static bool IsAlreadyPercentEncoded(string s)
        => _percentEncodedPattern.IsMatch(s);

    /// <summary>
    /// URL-encode payload an toàn: chỉ encode khi payload chưa có %XX.
    /// Tránh double-encode với wordlists đã có sẵn %20, %27, %2A, v.v.
    /// </summary>
    private static string SafeUrlEncode(string word)
        => IsAlreadyPercentEncoded(word) ? word : Uri.EscapeDataString(word);

    public static HttpRequestMessage Build(FuzzOptions options, string word)
    {
        string safeUrl  = options.Url.Replace("__TIME__", "3");
        string safeData = options.Data?.Replace("__TIME__", "3") ?? string.Empty;

        // Fix double encoding: chỉ encode khi FUZZ nằm trong URL VÀ payload chưa được encode sẵn.
        // Wordlist như sqli.txt chứa cả raw payload ("' OR 1=1") lẫn pre-encoded ("%27%20OR%201%3D1").
        // → Dùng SafeUrlEncode() thay vì gọi thẳng Uri.EscapeDataString().
        var urlWord = safeUrl.Contains("FUZZ") ? SafeUrlEncode(word) : word;
        var url = safeUrl.Replace("FUZZ", urlWord);

        var request = new HttpRequestMessage(
            new HttpMethod(options.Method),
            url
        );

        // Bug fix #2: Content-Type KHÔNG được set vào request.Headers —
        // .NET bắt buộc nó phải nằm trên request.Content.
        // → Tách Content-Type ra khỏi danh sách header, xử lý riêng.
        string? contentTypeOverride = null;
        foreach (var header in options.Headers ?? [])
        {
            var parts = header.Split(':', 2);
            if (parts.Length != 2) continue;

            var headerName  = parts[0].Trim();
            var headerValue = parts[1].Replace("\r", "").Replace("\n", "").Trim().Replace("FUZZ", word);

            if (headerName.Equals("Content-Type", StringComparison.OrdinalIgnoreCase))
            {
                contentTypeOverride = headerValue; // lưu lại, gán sau vào Content
            }
            else
            {
                request.Headers.TryAddWithoutValidation(headerName, headerValue);
            }
        }

        // Add cookies
        if (!string.IsNullOrEmpty(options.Cookie))
            request.Headers.TryAddWithoutValidation("Cookie", options.Cookie);

        // Add POST body
        if (!string.IsNullOrEmpty(safeData))
        {
            var body = safeData.Replace("\r", "").Replace("\n", "").Replace("FUZZ", word);

            // Bug fix #3: Dùng Content-Type từ header nếu có, fallback sang
            // application/json (phổ biến hơn application/x-www-form-urlencoded
            // khi gửi data thủ công qua UI)
            var contentType = contentTypeOverride
                           ?? options.ContentType
                           ?? "application/json";

            request.Content = new StringContent(body, System.Text.Encoding.UTF8, contentType);
        }

        return request;
    }
}