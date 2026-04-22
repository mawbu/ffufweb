using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        var listener = new HttpListener();
        listener.Prefixes.Add("http://127.0.0.1:9091/");
        listener.Start();
        Console.WriteLine("Test server listening on http://127.0.0.1:9091/");
        
        while (true)
        {
            var ctx = await listener.GetContextAsync();
            var path = ctx.Request.Url.AbsolutePath;
            
            ctx.Response.Headers.Add("Server", "TestServer");
            
            string responseString = "";
            byte[] buffer = null;

            if (path == "/" || path == "/home" || path == "/about" || path == "/contact")
            {
                ctx.Response.StatusCode = 200;
                responseString = "<html><body><h1>Welcome</h1></body></html>";
            }
            else if (path == "/api/config" || path == "/api%2Fconfig")
            {
                ctx.Response.StatusCode = 200;
                ctx.Response.ContentType = "application/json";
                responseString = "{\"version\":\"1.0\", \"api_key\":\"AKIA123X56789YYZ\"}";
            }
            else if (path == "/test_error")
            {
                ctx.Response.StatusCode = 500;
                responseString = "Traceback (most recent call last):\n  File \"server.py\", line 42\nZeroDivisionError";
            }
            else if (path == "/.env" || path == "/config.inc")
            {
                ctx.Response.StatusCode = 200;
                responseString = "DB_HOST=127.0.0.1\nDB_USER=root\nDB_PASSWORD=supersecret\n";
            }
            // SQLi test endpoint (POST body fuzzing)
            else if (path == "/api/search")
            {
                string bodyInput = "";
                using (var reader = new System.IO.StreamReader(ctx.Request.InputStream)) bodyInput = await reader.ReadToEndAsync();
                ctx.Response.ContentType = "application/json";
                
                if (bodyInput.Contains("'") || bodyInput.Contains("OR 1=1") || bodyInput.Contains("UNION"))
                {
                    ctx.Response.StatusCode = 500;
                    responseString = "{\"error\": \"SQLITE_ERROR: unrecognized token: near \\\"'\\\": syntax error\", \"query\": \"SELECT * FROM products WHERE name = '" + bodyInput.Replace("\"", "\\\"") + "'\"}";
                }
                else
                {
                    ctx.Response.StatusCode = 200;
                    responseString = "{\"results\": [], \"count\": 0}";
                }
            }
            // IDOR test endpoint
            else if (path.StartsWith("/api/users/") && path.Length > 11)
            {
                var idStr = path.Substring(11);
                ctx.Response.ContentType = "application/json";
                if (int.TryParse(idStr, out int id) && id >= 1 && id <= 5)
                {
                    ctx.Response.StatusCode = 200;
                    var ts = DateTime.UtcNow.ToString("o"); // dynamic timestamp
                    responseString = id switch
                    {
                        1 => $"{{\"id\":1,\"email\":\"admin@test.com\",\"role\":\"admin\",\"updatedAt\":\"{ts}\"}}",
                        2 => $"{{\"id\":2,\"email\":\"user2@test.com\",\"role\":\"user\",\"updatedAt\":\"{ts}\"}}",
                        3 => $"{{\"id\":3,\"email\":\"user3@test.com\",\"role\":\"user\",\"updatedAt\":\"{ts}\"}}",
                        _ => $"{{\"id\":{id},\"email\":\"user{id}@test.com\",\"role\":\"user\",\"updatedAt\":\"{ts}\"}}"
                    };
                }
                else
                {
                    ctx.Response.StatusCode = 404;
                    responseString = "{\"error\":\"User not found\"}";
                }
            }
            else
            {
                ctx.Response.StatusCode = 200;
                responseString = "Not Found.";
            }

            buffer = Encoding.UTF8.GetBytes(responseString);
            ctx.Response.ContentLength64 = buffer.Length;
            await ctx.Response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            ctx.Response.OutputStream.Close();
        }
    }
}
