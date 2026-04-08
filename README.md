# WebFuzzer

**WebFuzzer** là một web application fuzzer viết bằng C# (.NET 8), lấy cảm hứng từ [ffuf](https://github.com/ffuf/ffuf).  
Hỗ trợ concurrent fuzzing, lọc response linh hoạt, và xuất kết quả JSON/CSV.

---

## Cấu trúc dự án

```
WebFuzzer/
├── src/
│   ├── WebFuzzer.CLI/           # Entry point, CLI parsing (System.CommandLine)
│   │   ├── Program.cs
│   │   └── WebFuzzer.CLI.csproj
│   ├── WebFuzzer.Core/          # Logic chính
│   │   ├── Engine/
│   │   │   ├── FuzzEngine.cs        # Orchestrator chính
│   │   │   ├── RequestBuilder.cs    # Gửi HTTP request, tạo FuzzResult
│   │   │   └── WordlistReader.cs    # Đọc wordlist (file/stdin) async streaming
│   │   ├── Http/
│   │   │   ├── FuzzHttpClientFactory.cs  # Cấu hình HttpClient (proxy, TLS, redirect)
│   │   │   └── FuzzRequest.cs            # Model request đã build
│   │   ├── Filters/
│   │   │   ├── FilterConfig.cs      # Cấu hình filter/match
│   │   │   └── ResponseFilter.cs    # Logic lọc response
│   │   ├── Output/
│   │   │   ├── IFuzzReporter.cs     # Interface reporter
│   │   │   ├── ConsoleReporter.cs   # Output màu terminal
│   │   │   ├── JsonReporter.cs      # Output JSON
│   │   │   └── CsvReporter.cs       # Output CSV
│   │   └── Models/
│   │       ├── FuzzOptions.cs       # Options từ CLI
│   │       └── FuzzResult.cs        # Kết quả mỗi request
│   └── WebFuzzer.Tests/         # Unit tests (xUnit)
│       ├── ResponseFilterTests.cs
│       └── FuzzRequestTests.cs
├── wordlists/
│   ├── common.txt               # Web paths thông dụng
│   └── api-endpoints.txt        # REST/GraphQL API endpoints
├── WebFuzzer.sln
└── README.md
```

---

## Yêu cầu

- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

---

## Build & Chạy

```bash
# Restore packages
dotnet restore

# Build toàn bộ solution
dotnet build

# Chạy trực tiếp
dotnet run --project src/WebFuzzer.CLI -- -u https://example.com/FUZZ -w wordlists/common.txt (http://ffuf.me/)

# Publish thành binary đơn
dotnet publish src/WebFuzzer.CLI -c Release -r win-x64 --self-contained

#RUN WPF
dotnet run --project src/WebFuzzer.UI
dotnet watch run --project src/WebFuzzer.UI/WebFuzzer.UI.csproj
```

---

## Sử dụng

```
webfuzzer [options]

OPTIONS:
  -u, --url <url>              URL đích với placeholder FUZZ (bắt buộc)
  -w, --wordlist <path>        File wordlist hoặc '-' cho stdin (bắt buộc)
  -X, --method <method>        HTTP method [mặc định: GET]
  -H, --header <header>        Custom header "Name: Value" (dùng nhiều lần)
  -d, --data <body>            Request body (hỗ trợ FUZZ)
  -t, --threads <n>            Số concurrent requests [mặc định: 40]
      --timeout <s>            Timeout/request (giây) [mặc định: 10]
  -fc, --filter-code <codes>   Ẩn response có status code này
  -mc, --match-code <codes>    Chỉ hiện response có status code này
  -fs, --filter-size <bytes>   Ẩn response có Content-Length bằng
  -fw, --filter-words <n>      Ẩn response có số từ bằng
  -fl, --filter-lines <n>      Ẩn response có số dòng bằng
  -o,  --output-json <file>    Xuất kết quả ra JSON
       --output-csv <file>     Xuất kết quả ra CSV
  -k,  --ignore-tls            Bỏ qua lỗi TLS/SSL
  -L,  --follow-redirects      Tự động theo redirect
  -b,  --cookie <cookie>       Cookie "name=value"
       --delay <ms>            Delay giữa request (ms)
  -x,  --proxy <url>           Proxy URL
  -v,  --verbose               Hiện cả kết quả bị filter
  -fs 416                      Filter size = 416 bytes
  -fw 31                       Filter word count = 31
  -fl 16                       Filter line count = 16
  -ms 809                      Chỉ giữ size = 809
  -mw 76                       Chỉ giữ word count = 76
  -ml 13                       Chỉ giữ line count = 13
  -fr "Cannot GET"             Filter regex trong body
```

---

## Ví dụ

```bash
# Fuzz directory cơ bản, ẩn 404
webfuzzer -u https://example.com/FUZZ -w wordlists/common.txt

# Chỉ hiển thị 200, xuất kết quả JSON
webfuzzer -u https://example.com/FUZZ -w wordlists/common.txt -mc 200 -o results.json

# POST fuzzing với body
webfuzzer -u https://example.com/login -X POST -d "user=FUZZ&pass=test" -w wordlists/common.txt

# Dùng qua proxy (Burp Suite)
webfuzzer -u https://example.com/FUZZ -w wordlists/common.txt -x http://127.0.0.1:8080 -k

# API fuzzing với custom header
webfuzzer -u https://api.example.com/FUZZ \
  -w wordlists/api-endpoints.txt \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -mc 200 -t 20 -o api-results.json
```

---

## Chạy Tests

```bash
dotnet test src/WebFuzzer.Tests
```

---

## License

MIT

///////
200 OK, 301/302 Redirect, 401/403 Unauthorized/Forbidden
