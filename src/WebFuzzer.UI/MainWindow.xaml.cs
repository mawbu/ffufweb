using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using Microsoft.Win32;
using WebFuzzer.Core.Detection;
using WebFuzzer.Core.Engine;
using WebFuzzer.Core.Models;
using WebFuzzer.UI.ViewModels;
using Wpf.Ui.Appearance;
using Wpf.Ui.Controls;

namespace WebFuzzer.UI
{
    public partial class MainWindow : FluentWindow
    {
        // ── State ────────────────────────────────────────────────────────────
        private CancellationTokenSource? _cts;
        private readonly ObservableCollection<FuzzResultViewModel> _results = new();
        private ICollectionView? _resultsView;   // ✅ MỚI: dùng để filter theo severity
        private readonly Stopwatch _stopwatch = new();
        private long _requestCount;
        private long _matchCount;
        private long _vulnCount;                  // số vuln detected
        private long _bypassCount;                // số result bypass filter nhờ detection
        private long _confirmedCount;             // số kết quả đã được VERIFIED
        private System.Windows.Threading.DispatcherTimer? _statsTimer;

        // ── Detection ────────────────────────────────────────────────────────
        private readonly VulnerabilityDetector _detector = new();
        private Severity _filterSeverity = Severity.Normal; // filter threshold trong UI view

        public MainWindow()
        {
            ApplicationThemeManager.Apply(ApplicationTheme.Dark);
            InitializeComponent();

            // ✅ MỚI: dùng CollectionViewSource để filter/sort
            _resultsView = CollectionViewSource.GetDefaultView(_results);
            _resultsView.Filter = FilterBySeverity;
            ResultsGrid.ItemsSource = _resultsView;

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

        // ── Detection Filter ─────────────────────────────────────────────────

        /// <summary>
        /// Filter callback cho ICollectionView.
        /// Chỉ hiện row có severity >= _filterSeverity.
        /// </summary>
        private bool FilterBySeverity(object obj)
        {
            if (obj is not FuzzResultViewModel vm) return false;
            return _filterSeverity == Severity.Normal
                || vm.Detection.Severity >= _filterSeverity;
        }

        /// <summary>
        /// ✅ MỚI: Severity filter combobox handler.
        /// Index: 0=All, 1=Confirmed, 2=Likely+, 3=Suspicious+
        /// </summary>
        private void CmbSeverityFilter_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            _filterSeverity = CmbSeverityFilter.SelectedIndex switch
            {
                1 => Severity.Confirmed,
                2 => Severity.Likely,
                3 => Severity.Suspicious,
                _ => Severity.Normal
            };
            _resultsView?.Refresh();
        }

        // ── Detail Panel ─────────────────────────────────────────────────────

        /// <summary>
        /// ✅ MỚI: Hiển thị Detail Panel khi click row trong DataGrid.
        /// Chỉ hiện nếu row có detection signals.
        /// </summary>
        private void ResultsGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ResultsGrid.SelectedItem is not FuzzResultViewModel vm)
            {
                DetailPanel.Visibility = Visibility.Collapsed;
                return;
            }

            var detection = vm.Detection;

            // Không có signal nào → ẩn panel
            if (detection.Severity == Severity.Normal || detection.Signals.Count == 0)
            {
                DetailPanel.Visibility = Visibility.Collapsed;
                return;
            }

            // Cập nhật summary text trong header
            TxtDetailSummary.Text = detection.Summary;

            // Hiển thị trạng thái xác thực (Verified)
            if (vm.IsVerified)
            {
                BrdVerified.Visibility = Visibility.Visible;
                TxtConfirmation.Text = vm.Confirmation;
            }
            else
            {
                BrdVerified.Visibility = Visibility.Collapsed;
            }

            // Bind signal list
            SignalList.ItemsSource = detection.Signals;

            DetailPanel.Visibility = Visibility.Visible;
        }

        /// <summary>✅ MỚI: Đóng Detail Panel bằng nút ✕</summary>
        private void CloseDetailPanel_Click(object sender, RoutedEventArgs e)
        {
            DetailPanel.Visibility = Visibility.Collapsed;
            ResultsGrid.SelectedItem = null;
        }

        // ── Error Preset ─────────────────────────────────────────────────────
        private void CmbErrorPreset_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (CmbErrorPreset.SelectedItem is System.Windows.Controls.ComboBoxItem item
                && item.Tag is string pattern && !string.IsNullOrEmpty(pattern))
            {
                TxtMatchRegex.Text = pattern;
                UpdateCommandPreview();
            }
        }

        private void BtnPreset_Click(object sender, RoutedEventArgs e)
        {
            CmbErrorPreset.IsDropDownOpen = !CmbErrorPreset.IsDropDownOpen;
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
                sb.Append($" -H \"{TxtHeader.Text.Replace("\r", "").Replace("\n", " ").Trim()}\"");
            if (!string.IsNullOrWhiteSpace(TxtData.Text))
                sb.Append($" -d \"{TxtData.Text.Replace("\r", "").Replace("\n", " ").Trim()}\"");
            if (ChkAutoCalibrate.IsChecked == true)
                sb.Append(" -ac");
            if (ChkSmartDetection.IsChecked == true)
                sb.Append(" --detect");
            if (ChkEnableConfirmation.IsChecked == true)
                sb.Append(" --confirm");
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
            _vulnCount    = 0;
            _bypassCount  = 0;
            TxtStatRequests.Text = "0";
            TxtStatMatches.Text  = "0";
            TxtStatVulns.Text    = "0";
            TxtStatRps.Text      = "0";
            DetailPanel.Visibility = Visibility.Collapsed;

            SetRunningState(true);
            AppendTerminal("[WebFuzzer] Starting fuzzer...");
            AppendTerminal($"[WebFuzzer] Target: {TxtUrl.Text}");
            AppendTerminal($"[WebFuzzer] Wordlist: {TxtWordlist.Text}");

            _cts = new CancellationTokenSource();
            _stopwatch.Restart();
            _statsTimer!.Start();

            // ✅ MỚI: Thiết lập baseline trước khi fuzz nếu Smart Detection bật
            bool detectionEnabled = ChkSmartDetection.IsChecked == true;
            if (detectionEnabled)
            {
                await SetupBaselineAsync();
            }

            try
            {
                var options = BuildOptions();
                // Truyền detector vào engine — detection sẽ chạy TRƯỚC filter trong engine
                var detectorForEngine = (detectionEnabled && _detector.IsReady) ? _detector : null;
                var engine  = new FuzzEngine(options, OnResult, OnProgress, OnTerminalLine, detectorForEngine);
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
                AppendTerminal($"[WebFuzzer] Done. {_matchCount} matches" +
                    (_bypassCount > 0 ? $", {_bypassCount} retained by detection" : "") +
                    $", {_vulnCount} vulns found in {_stopwatch.Elapsed:mm\\:ss\\.fff}");
            }
        }

        /// <summary>
        /// ✅ MỚI: Gửi 3 request baseline với payload "aaaa1234xyz",
        /// lấy giá trị trung bình để thiết lập baseline cho VulnerabilityDetector.
        /// </summary>
        private async Task SetupBaselineAsync()
        {
            const string BaselinePayload = "aaaa1234xyz";
            AppendTerminal($"[Detection] Setting up baseline with payload '{BaselinePayload}'...");

            try
            {
                var options = BuildOptions();
                var baselineResults = new System.Collections.Generic.List<FuzzResult>();

                var handler = new System.Net.Http.HttpClientHandler
                {
                    AllowAutoRedirect = options.FollowRedirects,
                    ServerCertificateCustomValidationCallback = (_, _, _, _) => true
                };
                if (!string.IsNullOrEmpty(options.Proxy))
                {
                    handler.Proxy = new System.Net.WebProxy(options.Proxy);
                    handler.UseProxy = true;
                }

                using var client = new System.Net.Http.HttpClient(handler);
                client.Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds);

                // Gửi 3 request lấy trung bình
                for (int i = 0; i < 3; i++)
                {
                    if (_cts!.Token.IsCancellationRequested) break;

                    var request = RequestBuilder.Build(options, BaselinePayload);
                    var stopwatch = System.Diagnostics.Stopwatch.StartNew();

                    try
                    {
                        var response = await client.SendAsync(request, _cts.Token);
                        stopwatch.Stop();

                        var responseBody = await response.Content.ReadAsStringAsync(_cts.Token);

                        baselineResults.Add(new FuzzResult
                        {
                            Word = BaselinePayload,
                            Payload = BaselinePayload,
                            Url = request.RequestUri!.ToString(),
                            StatusCode = (int)response.StatusCode,
                            ContentLength = responseBody.Length,
                            WordCount = responseBody.Split(new[] { ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries).Length,
                            LineCount = responseBody.Split('\n').Length,
                            DurationMs = stopwatch.ElapsedMilliseconds,
                            ResponseBody = responseBody,
                            ContentType = response.Content.Headers.ContentType?.ToString(),
                            Timestamp = DateTime.UtcNow
                        });
                    }
                    catch (Exception ex)
                    {
                        AppendTerminal($"[Detection Error] Baseline request failed: {ex.Message}");
                    }

                    await Task.Delay(100, _cts!.Token); // nhỏ để tránh rate limit
                }

                if (baselineResults.Count > 0)
                {
                    // Guard: chỉ dùng 2xx responses — 5xx sẽ skew size/timing baseline
                    var valid2xx = baselineResults.Where(r => r.StatusCode >= 200 && r.StatusCode < 300).ToList();
                    if (valid2xx.Count > 0)
                    {
                        _detector.SetBaseline(valid2xx);
                        AppendTerminal($"[Detection] Baseline ready: " +
                            $"status={valid2xx[0].StatusCode}, " +
                            $"avgSize={valid2xx.Average(r => r.ContentLength):F0}, " +
                            $"avgTime={valid2xx.Average(r => r.DurationMs):F0}ms " +
                            $"(from {valid2xx.Count} 2xx samples)");
                    }
                    else
                    {
                        AppendTerminal("[Detection] ⚠ All baseline probes returned non-2xx — detection disabled.");
                    }
                }
                else
                {
                    AppendTerminal("[Detection] ⚠ Baseline failed — detection disabled for this run.");
                }
            }
            catch (Exception ex)
            {
                AppendTerminal($"[Detection] ⚠ Baseline error: {ex.Message}");
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
            _vulnCount = 0;
            TxtStatRequests.Text = "0";
            TxtStatMatches.Text  = "0";
            TxtStatVulns.Text    = "0";
            TxtStatRps.Text      = "0";
            DetailPanel.Visibility = Visibility.Collapsed;
            AppendTerminal("[WebFuzzer] Results cleared.");
        }

        // ── Callbacks từ FuzzEngine ──────────────────────────────────────────

        /// <summary>
        /// ✅ THAY ĐỔI: Nhận FuzzResult, wrap thành ViewModel, chạy detection,
        /// sau đó add vào collection. Tất cả trên Dispatcher thread.
        /// </summary>
        private void OnResult(FuzzResult result)
        {
            Dispatcher.Invoke(() =>
            {
                var vm = new FuzzResultViewModel(result);

                bool detectionEnabled = ChkSmartDetection.IsChecked == true;
                if (detectionEnabled && _detector.IsReady && !result.IsRetainedByDetection)
                {
                    // Đã pass filter bình thường (ko mượn cờ RetainedByDetection) — phân tích cho vui để hiện mức độ
                    var detection = _detector.Analyze(result, result.Word);
                    vm.Detection = detection;

                    if (detection.Severity >= Severity.Suspicious)
                    {
                        Interlocked.Increment(ref _vulnCount);
                        if (detection.Severity >= Severity.Likely)
                            AppendTerminal($"[VULN] {detection.Summary} | Payload: {result.Word}");
                    }
                }
                else if (result.IsRetainedByDetection)
                {
                    // Được detector cứu (retained) -> phân tích lấy result nếu trên UI
                    if (_detector.IsReady)
                    {
                        var detection = _detector.Analyze(result, result.Word);
                        vm.Detection = detection;
                    }
                    
                    // Nếu đã được VERIFIED bởi engine (V3), đồng bộ trạng thái
                    if (result.ConfirmationSummary != null && result.ConfirmationSummary.Contains("[VERIFIED]"))
                    {
                        AppendTerminal($"[✅ VERIFIED] {result.DetectedVulnType} found: {result.Word}");
                        Interlocked.Increment(ref _confirmedCount);
                    }

                    Interlocked.Increment(ref _vulnCount);
                    Interlocked.Increment(ref _bypassCount);
                }

                _results.Add(vm);
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
                TxtStatVulns.Text    = _vulnCount.ToString();
                TxtStatRps.Text      = rps.ToString();
                if (_bypassCount > 0)
                    TxtStatVulns.ToolTip = $"{_vulnCount} vuln signals, {_bypassCount} retained by detection";
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
                MatchCodes     = string.IsNullOrWhiteSpace(TxtMatchCodes.Text)
                                 ? new[] { "200", "301", "302" }
                                 : TxtMatchCodes.Text.Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToArray(),
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
                                 : TxtHeader.Text
                                     .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                                     .Select(h => h.Trim())
                                     .Where(h => h.Length > 0)
                                     .ToArray(),
                ContentType    = string.IsNullOrWhiteSpace(TxtContentType.Text) ? null : TxtContentType.Text.Trim(),
                Data           = string.IsNullOrWhiteSpace(TxtData.Text) ? null : TxtData.Text,
                AutoCalibrate   = ChkAutoCalibrate.IsChecked == true,
                EnableDetection = ChkSmartDetection.IsChecked == true,
                EnableConfirmation = ChkEnableConfirmation.IsChecked == true,
                Verbose         = ChkVerbose.IsChecked == true,
                FollowRedirects = ChkFollowRedirects.IsChecked == true,
                OutputFile      = string.IsNullOrWhiteSpace(TxtOutputFile.Text) ? null : TxtOutputFile.Text,
            };
        }

        private static string ResolveWordlistPath(string path)
        {
            if (string.IsNullOrWhiteSpace(path)) return path;
            if (Path.IsPathRooted(path)) return path;
            var resolved = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, path));
            return File.Exists(resolved) ? resolved : path;
        }

        // ── Validate ─────────────────────────────────────────────────────────
        private bool ValidateInputs()
        {
            var urlHasFuzz    = !string.IsNullOrWhiteSpace(TxtUrl.Text)    && TxtUrl.Text.Contains("FUZZ");
            var dataHasFuzz   = !string.IsNullOrWhiteSpace(TxtData.Text)   && TxtData.Text.Contains("FUZZ");
            var headerHasFuzz = !string.IsNullOrWhiteSpace(TxtHeader.Text) && TxtHeader.Text.Contains("FUZZ");

            if (string.IsNullOrWhiteSpace(TxtUrl.Text))
            {
                System.Windows.MessageBox.Show("URL cannot be empty.",
                    "Validation Error", System.Windows.MessageBoxButton.OK, MessageBoxImage.Warning);
                return false;
            }

            if (!urlHasFuzz && !dataHasFuzz && !headerHasFuzz)
            {
                System.Windows.MessageBox.Show(
                    "FUZZ placeholder must appear in at least one of:\n\n" +
                    "  • URL:           https://example.com/FUZZ\n" +
                    "  • POST Data:     {\"password\":\"FUZZ\"}\n" +
                    "  • Custom Header: User-Agent: FUZZ",
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
                ? new SolidColorBrush(Color.FromRgb(0x3F, 0xB9, 0x50))
                : new SolidColorBrush(Color.FromRgb(0x7D, 0x85, 0x90));

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

            // ✅ Export cả detection result
            var export = _results.Select(vm => new
            {
                vm.StatusCode, vm.Word, vm.Url,
                vm.ContentLength, vm.WordCount, vm.LineCount, vm.DurationMs,
                Detection = new
                {
                    Score    = vm.Detection.ConfidenceScore,
                    Severity = vm.Detection.Severity.ToString(),
                    VulnType = vm.Detection.PrimaryVulnType.ToString(),
                    vm.Detection.Summary,
                    Signals  = vm.Detection.Signals.Select(s => new
                    {
                        s.Name, s.Weight,
                        VulnType = s.VulnType.ToString(),
                        s.Evidence
                    })
                }
            });

            var json = JsonSerializer.Serialize(export, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(dlg.FileName, json);
            AppendTerminal($"[WebFuzzer] Exported {_results.Count} results to {dlg.FileName}");
        }

        private void ExportCsv_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new SaveFileDialog { Filter = "CSV (*.csv)|*.csv", FileName = "results.csv" };
            if (dlg.ShowDialog() != true) return;

            // ✅ MỚI: thêm cột Severity và VulnType vào CSV
            var sb = new StringBuilder("StatusCode,Word,Url,Size,Words,Lines,DurationMs,Severity,VulnType,ConfidenceScore\n");
            foreach (var vm in _results)
            {
                sb.AppendLine($"{vm.StatusCode},{EscapeCsv(vm.Word)},{EscapeCsv(vm.Url)}," +
                              $"{vm.ContentLength},{vm.WordCount},{vm.LineCount},{vm.DurationMs}," +
                              $"{vm.Detection.Severity},{vm.Detection.PrimaryVulnType},{vm.Detection.ConfidenceScore}");
            }

            File.WriteAllText(dlg.FileName, sb.ToString());
            AppendTerminal($"[WebFuzzer] Exported {_results.Count} results to {dlg.FileName}");
        }

        private static string EscapeCsv(string? value)
        {
            if (string.IsNullOrEmpty(value)) return "";
            return value.Contains(',') || value.Contains('"') || value.Contains('\n')
                ? $"\"{value.Replace("\"", "\"\"")}\""
                : value;
        }

        private void CopyCommand_Click(object sender, RoutedEventArgs e)
        {
            Clipboard.SetText(TxtCommandPreview.Text);
            AppendTerminal("[WebFuzzer] Command copied to clipboard.");
        }
    }
}