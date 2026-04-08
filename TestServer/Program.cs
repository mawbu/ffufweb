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
