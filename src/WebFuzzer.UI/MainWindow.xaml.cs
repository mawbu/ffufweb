using System;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using WebFuzzer.Core.Engine;
using WebFuzzer.Core.Models;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace WebFuzzer.UI
{
    public partial class MainWindow : FluentWindow
    {
        // ── State ────────────────────────────────────────────────────────────
        private CancellationTokenSource? _cts;
        private readonly ObservableCollection<FuzzResult> _results = new();
        private readonly Stopwatch _stopwatch = new();
        private long _requestCount;
        private long _matchCount;
        private System.Windows.Threading.DispatcherTimer? _statsTimer;

        public MainWindow()
        {
            ApplicationThemeManager.Apply(ApplicationTheme.Dark);
            InitializeComponent();
            ResultsGrid.ItemsSource = _results;

            // Mỗi khi thay đổi field → cập nhật command preview
            TxtUrl.TextChanged          += (s, e) => UpdateCommandPreview();
            TxtWordlist.TextChanged     += (s, e) => UpdateCommandPreview();
            TxtMatchCodes.TextChanged   += (s, e) => UpdateCommandPreview();
            TxtFilterCodes.TextChanged  += (s, e) => UpdateCommandPreview();
            TxtFilterSize.TextChanged   += (s, e) => UpdateCommandPreview();
            TxtMatchRegex.TextChanged   += (s, e) => UpdateCommandPreview();
            TxtFilterRegex.TextChanged  += (s, e) => UpdateCommandPreview();
            TxtThreads.TextChanged      += (s, e) => UpdateCommandPreview();
            TxtTimeout.TextChanged      += (s, e) => UpdateCommandPreview();
            TxtRate.TextChanged         += (s, e) => UpdateCommandPreview();
            TxtProxy.TextChanged        += (s, e) => UpdateCommandPreview();
            TxtHeader.TextChanged       += (s, e) => UpdateCommandPreview();
            TxtData.TextChanged         += (s, e) => UpdateCommandPreview();
            CmbMethod.SelectionChanged  += (s, e) => UpdateCommandPreview();
            ChkAutoCalibrate.Checked    += (s, e) => UpdateCommandPreview();
            ChkAutoCalibrate.Unchecked  += (s, e) => UpdateCommandPreview();
            ChkVerbose.Checked          += (s, e) => UpdateCommandPreview();
            ChkVerbose.Unchecked        += (s, e) => UpdateCommandPreview();

            // Stats timer — cập nhật req/sec mỗi 500ms
            _statsTimer = new System.Windows.Threading.DispatcherTimer
            {
                Interval = TimeSpan.FromMilliseconds(500)
            };
            _statsTimer.Tick += UpdateStats;

            UpdateCommandPreview();
        }

        // ── Command Preview ──────────────────────────────────────────────────
        private void UpdateCommandPreview()
        {
            var sb = new StringBuilder("webfuzzer");

            if (!string.IsNullOrWhiteSpace(TxtUrl.Text))
                sb.Append($" -u {TxtUrl.Text}");
            if (!string.IsNullOrWhiteSpace(TxtWordlist.Text))
                sb.Append($" -w {TxtWordlist.Text}");

            var method = (CmbMethod.SelectedItem as System.Windows.Controls.ComboBoxItem)?.Content?.ToString() ?? "GET";
            if (method != "GET") sb.Append($" -X {method}");

            if (!string.IsNullOrWhiteSpace(TxtMatchCodes.Text) && TxtMatchCodes.Text != "200,301,302")
                sb.Append($" -mc {TxtMatchCodes.Text}");
            if (!string.IsNullOrWhiteSpace(TxtFilterCodes.Text))
                sb.Append($" -fc {TxtFilterCodes.Text}");
            if (!string.IsNullOrWhiteSpace(TxtFilterSize.Text))
                sb.Append($" -fs {TxtFilterSize.Text}");
            if (!string.IsNullOrWhiteSpace(TxtMatchRegex.Text))
                sb.Append($" -mr \"{TxtMatchRegex.Text}\"");
            if (!string.IsNullOrWhiteSpace(TxtFilterRegex.Text))
                sb.Append($" -fr \"{TxtFilterRegex.Text}\"");
            if (TxtThreads.Text != "40")
                sb.Append($" -t {TxtThreads.Text}");
            if (TxtTimeout.Text != "10")
                sb.Append($" --timeout {TxtTimeout.Text}");
            if (TxtRate.Text != "0")
                sb.Append($" --rate {TxtRate.Text}");
            if (!string.IsNullOrWhiteSpace(TxtProxy.Text))
                sb.Append($" -x {TxtProxy.Text}");
            if (!string.IsNullOrWhiteSpace(TxtHeader.Text))
                sb.Append($" -H \"{TxtHeader.Text}\"");
            if (!string.IsNullOrWhiteSpace(TxtData.Text))
                sb.Append($" -d \"{TxtData.Text}\"");
            if (ChkAutoCalibrate.IsChecked == true)
                sb.Append(" -ac");
            if (ChkVerbose.IsChecked == true)
                sb.Append(" -v");

            TxtCommandPreview.Text = sb.ToString();
        }

        // ── Run ──────────────────────────────────────────────────────────────
        private async void BtnRun_Click(object sender, RoutedEventArgs e)
        {
            if (!ValidateInputs()) return;

            // Reset state
            _results.Clear();
            _requestCount = 0;
            _matchCount   = 0;
            TxtStatRequests.Text = "0";
            TxtStatMatches.Text  = "0";
            TxtStatRps.Text      = "0";

            SetRunningState(true);
            AppendTerminal("[WebFuzzer] Starting fuzzer...");
            AppendTerminal($"[WebFuzzer] Target: {TxtUrl.Text}");
            AppendTerminal($"[WebFuzzer] Wordlist: {TxtWordlist.Text}");

            _cts = new CancellationTokenSource();
            _stopwatch.Restart();
            _statsTimer!.Start();

            try
            {
                var options = BuildOptions();
                var engine  = new FuzzEngine(options, OnResult, OnProgress, OnTerminalLine);
                await engine.RunAsync(_cts.Token);
            }
            catch (OperationCanceledException)
            {
                AppendTerminal("[WebFuzzer] Fuzzing stopped by user.");
            }
            catch (Exception ex)
            {
                AppendTerminal($"[ERROR] {ex.Message}");
            }
            finally
            {
                _stopwatch.Stop();
                _statsTimer!.Stop();
                SetRunningState(false);
                UpdateStats(null, null);
                AppendTerminal($"[WebFuzzer] Done. {_matchCount} matches found in {_stopwatch.Elapsed:mm\\:ss\\.fff}");
            }
        }

        private void BtnStop_Click(object sender, RoutedEventArgs e)
        {
            _cts?.Cancel();
            AppendTerminal("[WebFuzzer] Stop requested...");
        }

        private void BtnClear_Click(object sender, RoutedEventArgs e)
        {
            _results.Clear();
            TxtStatRequests.Text = "0";
            TxtStatMatches.Text  = "0";
            TxtStatRps.Text      = "0";
            AppendTerminal("[WebFuzzer] Results cleared.");
        }

        // ── Callbacks từ FuzzEngine ──────────────────────────────────────────
        private void OnResult(FuzzResult result)
        {
            Dispatcher.Invoke(() =>
            {
                _results.Add(result);
                Interlocked.Increment(ref _matchCount);
            });
        }

        private void OnProgress(long requestCount, string currentWord)
        {
            Interlocked.Exchange(ref _requestCount, requestCount);
        }

        private void OnTerminalLine(string line)
        {
            Dispatcher.Invoke(() => AppendTerminal(line));
        }

        // ── Stats Timer ──────────────────────────────────────────────────────
        private long _lastRequestCount;
        private DateTime _lastStatTime = DateTime.Now;

        private void UpdateStats(object? sender, EventArgs? e)
        {
            Dispatcher.Invoke(() =>
            {
                var now      = DateTime.Now;
                var elapsed  = (now - _lastStatTime).TotalSeconds;
                var delta    = _requestCount - _lastRequestCount;
                var rps      = elapsed > 0 ? (int)(delta / elapsed) : 0;

                _lastRequestCount = _requestCount;
                _lastStatTime     = now;

                TxtStatRequests.Text = _requestCount.ToString();
                TxtStatMatches.Text  = _matchCount.ToString();
                TxtStatRps.Text      = rps.ToString();
            });
        }

        // ── Build FuzzOptions from UI ────────────────────────────────────────
        private FuzzOptions BuildOptions()
        {
            static HashSet<int>? ParseIntSet(string? raw) =>
                string.IsNullOrWhiteSpace(raw) ? null :
                raw.Split(',', StringSplitOptions.RemoveEmptyEntries)
                   .Select(s => int.Parse(s.Trim()))
                   .ToHashSet();

            var method = (CmbMethod.SelectedItem as System.Windows.Controls.ComboBoxItem)
                         ?.Content?.ToString() ?? "GET";

            return new FuzzOptions
            {
                Url            = TxtUrl.Text.Trim(),
                Wordlist       = ResolveWordlistPath(TxtWordlist.Text.Trim()),
                Method         = method,
                MatchCodes     = string.IsNullOrWhiteSpace(TxtMatchCodes.Text) ? null
                                 : TxtMatchCodes.Text.Split(','),
                FilterCodes    = string.IsNullOrWhiteSpace(TxtFilterCodes.Text) ? null
                                 : TxtFilterCodes.Text.Split(','),
                FilterSize     = ParseIntSet(TxtFilterSize.Text),
                MatchRegex     = string.IsNullOrWhiteSpace(TxtMatchRegex.Text) ? null : TxtMatchRegex.Text,
                FilterRegex    = string.IsNullOrWhiteSpace(TxtFilterRegex.Text) ? null : TxtFilterRegex.Text,
                Threads        = int.TryParse(TxtThreads.Text, out var t) ? t : 40,
                TimeoutSeconds = int.TryParse(TxtTimeout.Text, out var to) ? to : 10,
                RateLimit      = int.TryParse(TxtRate.Text, out var r) ? r : 0,
                Proxy          = string.IsNullOrWhiteSpace(TxtProxy.Text) ? null : TxtProxy.Text,
                Headers        = string.IsNullOrWhiteSpace(TxtHeader.Text) ? null
                                 : new[] { TxtHeader.Text },
                Data           = string.IsNullOrWhiteSpace(TxtData.Text) ? null : TxtData.Text,
                AutoCalibrate  = ChkAutoCalibrate.IsChecked == true,
                Verbose        = ChkVerbose.IsChecked == true,
                FollowRedirects = ChkFollowRedirects.IsChecked == true,
                OutputFile     = string.IsNullOrWhiteSpace(TxtOutputFile.Text) ? null : TxtOutputFile.Text,
            };
        }

        // Resolve đường dẫn tương đối theo thư mục chứa .exe (AppContext.BaseDirectory)
        // Tránh lỗi khi working directory khác (e.g. dotnet watch run)
        private static string ResolveWordlistPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return path;
            if (Path.IsPathRooted(path)) return path;  // đường dẫn tuyệt đối → giữ nguyên
            var resolved = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, path));
            return File.Exists(resolved) ? resolved : path; // fallback về path gốc nếu không tìm thấy
        }

        // ── Validate ─────────────────────────────────────────────────────────
        private bool ValidateInputs()
        {
            if (string.IsNullOrWhiteSpace(TxtUrl.Text) || !TxtUrl.Text.Contains("FUZZ"))
            {
                System.Windows.MessageBox.Show("URL must contain FUZZ placeholder.\nExample: https://example.com/FUZZ",
                    "Validation Error", System.Windows.MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            var wordlistPath = ResolveWordlistPath(TxtWordlist.Text.Trim());
            if (string.IsNullOrWhiteSpace(wordlistPath) || !File.Exists(wordlistPath))
            {
                System.Windows.MessageBox.Show(
                    $"Wordlist file not found:\n{wordlistPath}\n\nThư mục app: {AppContext.BaseDirectory}",
                    "Validation Error", System.Windows.MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }
            return true;
        }

        // ── UI State ─────────────────────────────────────────────────────────
        private void SetRunningState(bool running)
        {
            BtnRun.IsEnabled  = !running;
            BtnStop.IsEnabled = running;

            StatusDot.Fill = running
                ? new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50))   // green
                : new SolidColorBrush(Color.FromRgb(0x7D, 0x85, 0x90));  // gray

            TxtStatus.Text      = running ? "RUNNING" : "IDLE";
            TxtStatus.Foreground = running
                ? new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50))
                : new SolidColorBrush(Color.FromRgb(0x7D, 0x85, 0x90));
        }

        // ── Terminal ─────────────────────────────────────────────────────────
        private void AppendTerminal(string line)
        {
            TxtTerminal.Text += $"{DateTime.Now:HH:mm:ss.fff} {line}\n";
            TerminalScroll.ScrollToBottom();
        }

        private void ClearTerminal_Click(object sender, RoutedEventArgs e)
        {
            TxtTerminal.Text = "";
        }

        // ── File Dialogs ─────────────────────────────────────────────────────
        private void BrowseWordlist_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*",
                Title  = "Select Wordlist"
            };
            if (dlg.ShowDialog() == true)
                TxtWordlist.Text = dlg.FileName;
        }

        private void BrowseOutput_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog
            {
                Filter   = "JSON (*.json)|*.json|CSV (*.csv)|*.csv",
                FileName = "results.json",
                Title    = "Save Results"
            };
            if (dlg.ShowDialog() == true)
                TxtOutputFile.Text = dlg.FileName;
        }

        // ── Export ───────────────────────────────────────────────────────────
        private void ExportJson_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog { Filter = "JSON (*.json)|*.json", FileName = "results.json" };
            if (dlg.ShowDialog() != true) return;

            var json = JsonSerializer.Serialize(_results, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(dlg.FileName, json);
            AppendTerminal($"[WebFuzzer] Exported {_results.Count} results to {dlg.FileName}");
        }

        private void ExportCsv_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv", FileName = "results.csv" };
            if (dlg.ShowDialog() != true) return;

            var sb = new StringBuilder("StatusCode,Word,Url,Size,Words,Lines,DurationMs\n");
            foreach (var r in _results)
                sb.AppendLine($"{r.StatusCode},{r.Word},{r.Url},{r.ContentLength},{r.WordCount},{r.LineCount},{r.DurationMs}");

            File.WriteAllText(dlg.FileName, sb.ToString());
            AppendTerminal($"[WebFuzzer] Exported {_results.Count} results to {dlg.FileName}");
        }

        private void CopyCommand_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(TxtCommandPreview.Text);
            AppendTerminal("[WebFuzzer] Command copied to clipboard.");
        }
    }
}