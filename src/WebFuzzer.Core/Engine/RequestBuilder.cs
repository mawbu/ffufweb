using WebFuzzer.Core.Models;

namespace WebFuzzer.Core.Engine;

public static class RequestBuilder
{
    public static HttpRequestMessage Build(FuzzOptions options, string word)
    {
        // Bug fix #1: Chỉ URL-encode word khi FUZZ nằm trong URL.
        // Nếu FUZZ chỉ nằm trong POST Data (JSON payload), KHÔNG encode
        // vì encode sẽ phá vỡ ký tự đặc biệt như {, ", :
        var urlWord = options.Url.Contains("FUZZ") ? Uri.EscapeDataString(word) : word;
        var url = options.Url.Replace("FUZZ", urlWord);

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
        if (!string.IsNullOrEmpty(options.Data))
        {
            var body = options.Data.Replace("\r", "").Replace("\n", "").Replace("FUZZ", word);

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