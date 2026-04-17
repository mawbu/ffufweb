using System.Windows;

namespace WebFuzzer.UI;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        // ✅ Global exception catcher — log vào file thay vì crash âm thầm
        DispatcherUnhandledException += (sender, ex) =>
        {
            var msg = $"[CRASH] Unhandled UI Exception:\n{ex.Exception}";
            try { System.IO.File.AppendAllText("crash.log", $"{DateTime.Now:s}\n{msg}\n\n"); } catch { }
            System.Windows.MessageBox.Show(
                $"An unexpected error occurred:\n\n{ex.Exception.Message}",
                "WebFuzzer — Error",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            ex.Handled = true; // ✔ Không crash app, chỉ log
        };

        // ✅ Catch exception từ background Task không được await
        System.Threading.Tasks.TaskScheduler.UnobservedTaskException += (sender, ex) =>
        {
            var msg = $"[CRASH] Unobserved Task Exception:\n{ex.Exception}";
            try { System.IO.File.AppendAllText("crash.log", $"{DateTime.Now:s}\n{msg}\n\n"); } catch { }
            ex.SetObserved();
        };
    }
}

