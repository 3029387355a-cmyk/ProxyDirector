// ProxyDirector — 本地多代理自动测速择优器
// 构建要求: Windows 自带 .NET Framework 4.8 编译器 (csc), C# 5 语法
// 模块: 配置 / 端口发现 / 协议识别 / 测速 / 迟滞决策 / 系统代理切换 / 引擎线程 / WinForms GUI
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Web.Script.Serialization;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ProxyDirector
{
    // ============================ 配置 ============================
    public class ProxyEntry
    {
        public string name { get; set; }
        public string processName { get; set; }   // 用于重新扫描的进程名
        public string host { get; set; }          // 通常 127.0.0.1
        public int port { get; set; }
        public string protocol { get; set; }      // HTTP / SOCKS5 / UNKNOWN (识别结果)
    }

    public class AppConfig
    {
        public int checkIntervalSeconds { get; set; }
        public int switchThresholdPercent { get; set; }
        public int minDwellMinutes { get; set; }
        public int probeTimeoutMs { get; set; }
        public int speedTimeoutSeconds { get; set; }
        public bool autoSwitch { get; set; }
        public List<string> testUrls { get; set; }
        public List<ProxyEntry> proxies { get; set; }

        public static AppConfig CreateDefault()
        {
            AppConfig c = new AppConfig();
            c.checkIntervalSeconds = 60;
            c.switchThresholdPercent = 25;
            c.minDwellMinutes = 5;
            c.probeTimeoutMs = 800;
            c.speedTimeoutSeconds = 8;
            c.autoSwitch = true;
            c.testUrls = new List<string>();
            c.testUrls.Add("https://www.gstatic.com/generate_204");
            c.testUrls.Add("http://www.msftconnecttest.com/connecttest.txt");
            c.testUrls.Add("http://captive.apple.com/hotspot-detect.html");
            c.proxies = new List<ProxyEntry>();
            return c;
        }
    }

    public static class ConfigStore
    {
        public static readonly string BaseDir = AppDomain.CurrentDomain.BaseDirectory;
        public static readonly string ConfigPath = Path.Combine(BaseDir, "config.json");
        public static readonly string LogPath = Path.Combine(BaseDir, "proxy.log");
        public static readonly string RuntimeDir = Path.Combine(BaseDir, "runtime");

        public static AppConfig Load()
        {
            try
            {
                if (File.Exists(ConfigPath))
                {
                    JavaScriptSerializer js = new JavaScriptSerializer();
                    AppConfig cfg = js.Deserialize<AppConfig>(File.ReadAllText(ConfigPath));
                    if (cfg != null && cfg.proxies != null) return cfg;
                }
            }
            catch (Exception ex) { Logger.Log("配置读取失败, 使用默认: " + ex.Message); }
            AppConfig def = AppConfig.CreateDefault();
            Save(def);
            return def;
        }

        public static void Save(AppConfig cfg)
        {
            try
            {
                Directory.CreateDirectory(RuntimeDir);
                JavaScriptSerializer js = new JavaScriptSerializer();
                File.WriteAllText(ConfigPath, js.Serialize(cfg));
            }
            catch (Exception ex) { Logger.Log("配置写入失败: " + ex.Message); }
        }
    }

    // ============================ 日志 ============================
    public static class Logger
    {
        private static readonly object _lock = new object();
        public static void Log(string msg)
        {
            try
            {
                lock (_lock)
                {
                    string line = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "  " + msg + Environment.NewLine;
                    File.AppendAllText(ConfigStore.LogPath, line);
                    // 简单轮转: 超过 2MB 截断保留后半
                    FileInfo fi = new FileInfo(ConfigStore.LogPath);
                    if (fi.Exists && fi.Length > 2 * 1024 * 1024)
                    {
                        string all = File.ReadAllText(ConfigStore.LogPath);
                        File.WriteAllText(ConfigStore.LogPath, all.Substring(all.Length / 2));
                    }
                }
            }
            catch { }
        }
    }

    // ============================ 端口发现 ============================
    public class PortInfo { public int port; public string owner; }

    public static class PortDiscovery
    {
        // 进程名前缀 -> 匹配进程家族监听的 TCP 端口列表 (含归属进程名)
        // 输入客户端名可同时覆盖其全部进程 (UI / 内核 / 助手服务);
        // 非代理端口(如 HelperService 的 47890)由上层协议识别阶段排除。
        public static List<PortInfo> GetListeningPortInfos(string processNamePrefix)
        {
            List<PortInfo> result = new List<PortInfo>();
            try
            {
                List<int> pids = new List<int>();
                Dictionary<int, string> pidOwner = new Dictionary<int, string>();
                foreach (Process p in Process.GetProcesses())
                {
                    try
                    {
                        if (p.ProcessName.StartsWith(processNamePrefix, StringComparison.OrdinalIgnoreCase))
                        {
                            pids.Add(p.Id);
                            pidOwner[p.Id] = p.ProcessName;
                        }
                    }
                    catch { }
                }
                if (pids.Count == 0) return result;

                ProcessStartInfo psi = new ProcessStartInfo();
                psi.FileName = "netstat.exe";
                psi.Arguments = "-ano";
                psi.UseShellExecute = false;
                psi.RedirectStandardOutput = true;
                psi.CreateNoWindow = true;
                using (Process proc = Process.Start(psi))
                {
                    string output = proc.StandardOutput.ReadToEnd();
                    proc.WaitForExit(5000);
                    Regex rx = new Regex(@"^\s*TCP\s+(\S+?):(\d+)\s+\S+\s+(\S+)\s+(\d+)\s*$",
                                         RegexOptions.IgnoreCase | RegexOptions.Multiline);
                    foreach (Match m in rx.Matches(output))
                    {
                        string state = m.Groups[3].Value.ToUpperInvariant();
                        int pid = int.Parse(m.Groups[4].Value);
                        int port = int.Parse(m.Groups[2].Value);
                        if (state.Contains("LISTEN") && Array.IndexOf(pids.ToArray(), pid) >= 0 && port > 0)
                        {
                            bool dup = false;
                            foreach (PortInfo pi in result) if (pi.port == port) { dup = true; break; }
                            if (!dup)
                            {
                                PortInfo info = new PortInfo();
                                info.port = port;
                                string owner; pidOwner.TryGetValue(pid, out owner);
                                info.owner = owner == null ? "" : owner;
                                result.Add(info);
                            }
                        }
                    }
                }
                result.Sort(delegate(PortInfo a, PortInfo b) { return a.port.CompareTo(b.port); });
            }
            catch (Exception ex) { Logger.Log("端口发现失败[" + processNamePrefix + "]: " + ex.Message); }
            return result;
        }

        public static List<int> GetListeningPorts(string processName)
        {
            List<int> result = new List<int>();
            foreach (PortInfo pi in GetListeningPortInfos(processName)) result.Add(pi.port);
            return result;
        }
    }

    // ============================ 协议识别 ============================
    public static class ProtocolProbe
    {
        // 对本地端口做最小协议握手, 区分 HTTP 代理 / SOCKS5 / 非代理。零外网流量。
        public static string Identify(string host, int port, int timeoutMs)
        {
            // 1) HTTP CONNECT 探测
            try
            {
                using (TcpClient tc = new TcpClient())
                {
                    IAsyncResult ar = tc.BeginConnect(host, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) { tc.Close(); }
                    else
                    {
                        tc.EndConnect(ar);
                        tc.ReceiveTimeout = timeoutMs;
                        tc.SendTimeout = timeoutMs;
                        byte[] req = Encoding.ASCII.GetBytes(
                            "CONNECT 127.0.0.1:80 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
                        tc.GetStream().Write(req, 0, req.Length);
                        byte[] buf = new byte[256];
                        int n = tc.GetStream().Read(buf, 0, buf.Length);
                        if (n > 0)
                        {
                            string head = Encoding.ASCII.GetString(buf, 0, Math.Min(n, 40)).ToUpperInvariant();
                            if (head.StartsWith("HTTP/1") && head.Contains(" 200")) return "HTTP";
                        }
                    }
                }
            }
            catch { }

            // 2) SOCKS5 问候探测
            try
            {
                using (TcpClient tc = new TcpClient())
                {
                    IAsyncResult ar = tc.BeginConnect(host, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) { tc.Close(); }
                    else
                    {
                        tc.EndConnect(ar);
                        tc.ReceiveTimeout = timeoutMs;
                        tc.SendTimeout = timeoutMs;
                        byte[] hello = new byte[] { 0x05, 0x01, 0x00 };  // 无认证请求
                        tc.GetStream().Write(hello, 0, 3);
                        byte[] buf = new byte[8];
                        int n = tc.GetStream().Read(buf, 0, buf.Length);
                        if (n >= 2 && buf[0] == 0x05) return "SOCKS5";
                    }
                }
            }
            catch { }
            return "UNKNOWN";
        }
    }

    // ============================ 测速 ============================
    public class SpeedResult
    {
        public bool ok;
        public int latencyMs;
        public string viaUrl;
    }

    public static class SpeedTester
    {
        private static bool _tlsSet = false;
        // 经指定代理端口做端到端请求, 依次尝试目标池
        public static SpeedResult Test(string host, int port, AppConfig cfg)
        {
            if (!_tlsSet)
            {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11;
                _tlsSet = true;
            }
            foreach (string url in cfg.testUrls)
            {
                HttpClientHandler h = new HttpClientHandler();
                h.Proxy = new WebProxy("http://" + host + ":" + port.ToString());
                h.UseProxy = true;
                h.UseCookies = false;
                h.AllowAutoRedirect = false;
                using (HttpClient hc = new HttpClient(h))
                {
                    hc.Timeout = TimeSpan.FromSeconds(cfg.speedTimeoutSeconds);
                    hc.DefaultRequestHeaders.ConnectionClose = true;
                    Stopwatch sw = Stopwatch.StartNew();
                    try
                    {
                        using (HttpResponseMessage resp = hc.GetAsync(url).Result)
                        {
                            sw.Stop();
                            if (resp.IsSuccessStatusCode)
                            {
                                SpeedResult r = new SpeedResult();
                                r.ok = true; r.latencyMs = (int)sw.ElapsedMilliseconds; r.viaUrl = url;
                                return r;
                            }
                        }
                    }
                    catch { sw.Stop(); }
                }
            }
            return new SpeedResult();  // ok=false
        }
    }

    // ============================ 系统代理 ============================
    public static class SystemProxy
    {
        [DllImport("wininet.dll", SetLastError = true)]
        private static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
        private const int INTERNET_OPTION_SETTINGS_CHANGED = 39;
        private const int INTERNET_OPTION_REFRESH = 37;

        private static RegistryKey OpenKey() { return Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings", true); }

        public static string GetCurrent()
        {
            try
            {
                using (RegistryKey k = OpenKey())
                {
                    if (k == null) return "";
                    int enable = (int)k.GetValue("ProxyEnable", 0);
                    string server = (string)k.GetValue("ProxyServer", "");
                    return (enable == 1 ? "[ON] " : "[off] ") + server;
                }
            }
            catch { return ""; }
        }

        public static void Set(string server)
        {
            using (RegistryKey k = OpenKey())
            {
                k.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                k.SetValue("ProxyServer", server);
            }
            Broadcast();
        }

        public static void Disable()
        {
            using (RegistryKey k = OpenKey())
            {
                k.SetValue("ProxyEnable", 0, RegistryValueKind.DWord);
            }
            Broadcast();
        }

        private static void Broadcast()
        {
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_SETTINGS_CHANGED, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, INTERNET_OPTION_REFRESH, IntPtr.Zero, 0);
        }
    }

    // ============================ 决策 ============================
    public enum DecisionType { None, SwitchTo, AllDown }

    public class Decision
    {
        public DecisionType type;
        public string targetName;   // SwitchTo 时有效
        public string reason;
    }

    public static class DecisionMaker
    {
        // 迟滞决策: 全部失联不动作; 当前失联(连续 failStreak>=2)切最快;
        // 候选比当前快 threshold% 且距上次切换 >= minDwell 才切
        public static Decision Decide(List<ProxyState> states, AppConfig cfg,
                                      string currentName, DateTime lastSwitch,
                                      Dictionary<string, int> failStreak)
        {
            List<ProxyState> alive = states.Where(s => s.linkOk).ToList();
            if (alive.Count == 0)
                return new Decision { type = DecisionType.AllDown, reason = "所有代理链路均不可用" };

            ProxyState best = alive.OrderBy(s => s.latencyMs).First();

            // 当前生效的代理是否存在且可用
            ProxyState current = null;
            foreach (ProxyState s in states) if (s.cfg.name == currentName) { current = s; break; }

            if (current == null || !current.linkOk)
            {
                int streak = current == null ? 99 : GetStreak(failStreak, current.cfg.name);
                string why = current == null ? "无生效代理" : ("当前代理连续失败 " + streak + " 轮");
                if (current == null || streak >= 2)
                    return new Decision { type = DecisionType.SwitchTo, targetName = best.cfg.name,
                                          reason = why + " -> 切换至 " + best.cfg.name };
                return new Decision { type = DecisionType.None, reason = why + ", 等待确认" };
            }

            // 当前可用: 比较是否值得切换 (迟滞 + 最小停留)
            if (best.cfg.name == current.cfg.name)
                return new Decision { type = DecisionType.None, reason = "当前即最优" };

            if (DateTime.Now - lastSwitch < TimeSpan.FromMinutes(cfg.minDwellMinutes))
                return new Decision { type = DecisionType.None, reason = "最小停留时间内不切换" };

            int gain = (int)((current.latencyMs - best.latencyMs) * 100.0 / Math.Max(current.latencyMs, 1));
            if (gain >= cfg.switchThresholdPercent)
                return new Decision { type = DecisionType.SwitchTo, targetName = best.cfg.name,
                                      reason = best.cfg.name + " 快 " + gain + "% (" + best.latencyMs + "ms vs " + current.latencyMs + "ms)" };
            return new Decision { type = DecisionType.None, reason = "差距不足 (" + gain + "% < " + cfg.switchThresholdPercent + "%)" };
        }

        private static int GetStreak(Dictionary<string, int> d, string k)
        {
            int v; if (d.TryGetValue(k, out v)) return v; return 0;
        }
    }

    // ============================ 引擎 ============================
    public class ProxyState
    {
        public ProxyEntry cfg;
        public bool linkOk;
        public int latencyMs;
        public string detail;       // 最后一次结果描述
    }

    public class EngineSnapshot
    {
        public List<ProxyState> states = new List<ProxyState>();
        public string currentName = "";
        public string lastDecision = "";
        public string lastSwitchInfo = "";
        public int secondsToNext = 0;
        public bool autoSwitch;
        public string sysProxy = "";
        public string externalConflict = "";
    }

    public class Engine
    {
        private readonly object _lock = new object();
        private AppConfig _cfg;
        private Thread _thread;
        private volatile bool _running;
        private volatile bool _forceCheck;
        private ManualResetEvent _wake = new ManualResetEvent(false);
        private string _currentName = "";
        private DateTime _lastSwitch = DateTime.MinValue;
        private Dictionary<string, int> _failStreak = new Dictionary<string, int>();
        private Dictionary<string, bool> _lastLinkOk = new Dictionary<string, bool>();

        public Engine(AppConfig cfg)
        {
            _cfg = cfg;
            // 启动时若系统代理已指向某个受管端口, 认可为当前状态
            string cur = SystemProxy.GetCurrent();
            foreach (ProxyEntry p in _cfg.proxies)
            {
                if (cur.Contains(p.host + ":" + p.port.ToString())) { _currentName = p.name; break; }
            }
            DetectExternalConflict();
        }

        private void DetectExternalConflict()
        {
            // 若系统代理开着但不是指向任何受管端口 => 可能是某代理客户端的开关在抢
            string cur = SystemProxy.GetCurrent();
            bool on = cur.StartsWith("[ON]");
            bool ours = false;
            foreach (ProxyEntry p in _cfg.proxies)
                if (cur.Contains(p.host + ":" + p.port.ToString())) { ours = true; break; }
            lock (_lock)
            {
                if (on && !ours)
                    _snap.externalConflict = "系统代理被外部程序设置为 " + cur.Substring(5) + "，请关闭机场客户端的系统代理开关";
                else
                    _snap.externalConflict = "";
            }
        }

        private EngineSnapshot _snap = new EngineSnapshot();

        public EngineSnapshot Snapshot
        {
            get { lock (_lock) { return CloneSnap(); } }
        }

        private EngineSnapshot CloneSnap()
        {
            EngineSnapshot s = new EngineSnapshot();
            s.currentName = _snap.currentName;
            s.lastDecision = _snap.lastDecision;
            s.lastSwitchInfo = _snap.lastSwitchInfo;
            s.secondsToNext = _snap.secondsToNext;
            s.autoSwitch = _snap.autoSwitch;
            s.sysProxy = _snap.sysProxy;
            s.externalConflict = _snap.externalConflict;
            foreach (ProxyState st in _snap.states)
            {
                ProxyState c = new ProxyState();
                c.cfg = st.cfg; c.linkOk = st.linkOk; c.latencyMs = st.latencyMs; c.detail = st.detail;
                s.states.Add(c);
            }
            return s;
        }

        public void Start()
        {
            _running = true;
            _thread = new Thread(RunLoop);
            _thread.IsBackground = true;
            _thread.Start();
        }

        public void Stop() { _running = false; _wake.Set(); }

        public void ForceCheck() { _forceCheck = true; _wake.Set(); }

        public void SetAutoSwitch(bool on)
        {
            lock (_lock)
            {
                _cfg.autoSwitch = on;
                _snap.autoSwitch = on;
            }
            ConfigStore.Save(_cfg);
            Logger.Log("自动切换: " + (on ? "启用" : "暂停"));
        }

        public void UpdateSettings(int interval, int threshold, int dwell)
        {
            lock (_lock)
            {
                _cfg.checkIntervalSeconds = interval;
                _cfg.switchThresholdPercent = threshold;
                _cfg.minDwellMinutes = dwell;
            }
            ConfigStore.Save(_cfg);
        }

        public void ReloadConfig()
        {
            lock (_lock) { _cfg = ConfigStore.Load(); }
            DetectExternalConflict();
        }

        // 对所有代理重新扫描端口并识别协议, 更新配置
        public void RescanAll()
        {
            foreach (ProxyEntry p in _cfg.proxies)
            {
                try
                {
                    List<int> ports = PortDiscovery.GetListeningPorts(p.processName);
                    if (ports.Count > 0)
                    {
                        int bestPort = 0; string bestProto = "UNKNOWN";
                        foreach (int pt in ports)
                        {
                            string proto = ProtocolProbe.Identify(p.host, pt, _cfg.probeTimeoutMs);
                            if (proto != "UNKNOWN") { bestPort = pt; bestProto = proto; break; }
                        }
                        if (bestPort != 0)
                        {
                            if (p.port != bestPort)
                                Logger.Log("重新扫描: " + p.name + " 端口 " + p.port + " -> " + bestPort);
                            p.port = bestPort;
                            p.protocol = bestProto;
                        }
                    }
                }
                catch (Exception ex) { Logger.Log("重新扫描异常[" + p.name + "]: " + ex.Message); }
            }
            ConfigStore.Save(_cfg);
            ForceCheck();
        }

        // 手动切换
        public void ManualSwitch(string name)
        {
            ProxyEntry target = null;
            foreach (ProxyEntry p in _cfg.proxies) if (p.name == name) { target = p; break; }
            if (target == null) return;
            SystemProxy.Set(target.host + ":" + target.port.ToString());
            lock (_lock)
            {
                _currentName = name;
                _lastSwitch = DateTime.Now;
                _snap.currentName = name;
                _snap.lastSwitchInfo = DateTime.Now.ToString("HH:mm:ss") + " 手动切换 -> " + name;
            }
            Logger.Log("手动切换 -> " + name + " (" + target.host + ":" + target.port + ")");
        }

        private void RunLoop()
        {
            int countdown = 3;  // 启动后 3 秒做第一轮
            while (_running)
            {
                int sleepStep = Math.Min(countdown, 1);
                _wake.WaitOne(1000);
                _wake.Reset();
                if (!_running) break;
                if (_forceCheck) { countdown = 0; _forceCheck = false; }
                else countdown -= 1;

                lock (_lock) { _snap.secondsToNext = Math.Max(countdown, 0); }
                if (countdown <= 0)
                {
                    RunCheck();
                    lock (_lock) { countdown = _cfg.checkIntervalSeconds; }
                }
            }
        }

        public void RunCheck()
        {
            // 顶层保护: 引擎线程任何异常都不允许终止循环
            try { RunCheckInner(); }
            catch (Exception ex) { Logger.Log("引擎轮次异常: " + ex); }
        }

        private void RunCheckInner()
        {
            List<ProxyState> states = new List<ProxyState>();
            foreach (ProxyEntry p in _cfg.proxies)
            {
                ProxyState st = new ProxyState();
                st.cfg = p;
                SpeedResult r = SpeedTester.Test(p.host, p.port, _cfg);
                st.linkOk = r.ok;
                st.latencyMs = r.latencyMs;
                st.detail = r.ok ? (r.latencyMs + "ms via " + ShortUrl(r.viaUrl)) : "不可用";
                states.Add(st);
                // 失败计数
                if (!r.ok)
                {
                    int v; _failStreak.TryGetValue(p.name, out v);
                    _failStreak[p.name] = v + 1;
                }
                else _failStreak[p.name] = 0;
            }

            string decisionInfo = "";
            Decision d = DecisionMaker.Decide(states, _cfg, _currentName, _lastSwitch, _failStreak);
            decisionInfo = d.type.ToString() + ": " + d.reason;

            bool doSwitch = false;
            if (d.type == DecisionType.SwitchTo)
            {
                if (_cfg.autoSwitch) doSwitch = true;
                else decisionInfo += " (自动切换已暂停, 未执行)";
            }
            if (d.type == DecisionType.AllDown)
                Logger.Log("警告: " + d.reason);

            if (doSwitch)
            {
                ProxyEntry target = null;
                foreach (ProxyEntry p in _cfg.proxies) if (p.name == d.targetName) { target = p; break; }
                if (target != null)
                {
                    SystemProxy.Set(target.host + ":" + target.port.ToString());
                    lock (_lock)
                    {
                        _currentName = target.name;
                        _lastSwitch = DateTime.Now;
                        _snap.lastSwitchInfo = DateTime.Now.ToString("HH:mm:ss") + " -> " + target.name + " (" + d.reason + ")";
                    }
                    Logger.Log("自动切换 -> " + target.name + " | " + d.reason + " | 切换后系统代理: " + SystemProxy.GetCurrent());
                }
            }

            lock (_lock)
            {
                _snap.states = states;
                _snap.currentName = _currentName;
                _snap.lastDecision = decisionInfo;
                _snap.autoSwitch = _cfg.autoSwitch;
                _snap.sysProxy = SystemProxy.GetCurrent();
            }

            // ---- 运行日志: 链路状态变化 + 本轮汇总 ----
            foreach (ProxyState st in states)
            {
                bool prev;
                if (_lastLinkOk.TryGetValue(st.cfg.name, out prev))
                {
                    if (prev != st.linkOk)
                        Logger.Log("链路变化: " + st.cfg.name + " " + (prev ? "可用" : "不可用")
                                   + " -> " + (st.linkOk ? "可用" : "不可用"));
                }
                _lastLinkOk[st.cfg.name] = st.linkOk;
            }
            StringBuilder sum = new StringBuilder();
            foreach (ProxyState st in states)
            {
                if (sum.Length > 0) sum.Append(" | ");
                sum.Append(st.cfg.name + "=" + (st.linkOk ? st.latencyMs + "ms" : "不可用"));
            }
            if (sum.Length == 0) sum.Append("(无已配置代理)");
            Logger.Log("测速汇总: " + sum + " | 决策: " + decisionInfo
                       + (_cfg.autoSwitch ? "" : " [自动切换暂停中]"));
        }

        private static string ShortUrl(string u)
        {
            try { Uri uri = new Uri(u); return uri.Host; }
            catch { return u; }
        }
    }

    // ============================ 添加向导 ============================
    public class AddProxyForm : Form
    {
        private TextBox _procBox;
        private Button _scanBtn;
        private CheckedListBox _candList;
        private TextBox _nameBox;
        private Button _okBtn, _cancelBtn;
        private Label _hint;
        private ProgressBar _progress;   // 扫描期间的滚动加载动画
        public List<ProxyEntry> Added = new List<ProxyEntry>();

        public AddProxyForm()
        {
            Text = "添加代理";
            FormBorderStyle = FormBorderStyle.FixedDialog;
            MaximizeBox = false; MinimizeBox = false;
            StartPosition = FormStartPosition.CenterParent;
            ClientSize = new Size(440, 380);

            Label l1 = new Label(); l1.Text = "代理客户端核心进程名 (通常为 客户端名+Core):";
            l1.Location = new Point(12, 12); l1.AutoSize = true;
            Controls.Add(l1);

            _procBox = new TextBox();
            _procBox.Location = new Point(12, 32); _procBox.Width = 300;
            Controls.Add(_procBox);

            _scanBtn = new Button(); _scanBtn.Text = "扫描端口";
            _scanBtn.Location = new Point(320, 30); _scanBtn.Width = 100;
            _scanBtn.Click += OnScan;
            Controls.Add(_scanBtn);

            _hint = new Label(); _hint.Text = "识别结果 (勾选要添加的端口):";
            _hint.Location = new Point(12, 64); _hint.AutoSize = true;
            Controls.Add(_hint);

            _progress = new ProgressBar();
            _progress.Style = ProgressBarStyle.Marquee;
            _progress.MarqueeAnimationSpeed = 40;
            _progress.Location = new Point(12, 62);
            _progress.Size = new Size(408, 18);
            _progress.Visible = false;
            Controls.Add(_progress);

            _candList = new CheckedListBox();
            _candList.Location = new Point(12, 82); _candList.Size = new Size(408, 180);
            _candList.CheckOnClick = true;
            Controls.Add(_candList);

            Label l2 = new Label(); l2.Text = "显示名称:"; l2.Location = new Point(12, 272); l2.AutoSize = true;
            Controls.Add(l2);
            _nameBox = new TextBox(); _nameBox.Location = new Point(80, 269); _nameBox.Width = 180;
            Controls.Add(_nameBox);

            _okBtn = new Button(); _okBtn.Text = "添加"; _okBtn.DialogResult = DialogResult.None;
            _okBtn.Location = new Point(240, 310); _okBtn.Click += OnOk;
            Controls.Add(_okBtn);
            _cancelBtn = new Button(); _cancelBtn.Text = "取消";
            _cancelBtn.DialogResult = DialogResult.Cancel; _cancelBtn.Location = new Point(340, 310);
            Controls.Add(_cancelBtn);
        }

        private void OnScan(object sender, EventArgs e)
        {
            string proc = _procBox.Text.Trim();
            if (proc.Length == 0) { MessageBox.Show("请输入进程名"); return; }

            // 进入扫描状态: 动画 + 禁用按钮, 实际工作放后台线程避免界面冻结
            _candList.Items.Clear();
            _candList.Items.Add("正在扫描端口并识别协议, 请稍候...", false);
            _scanBtn.Enabled = false;
            _okBtn.Enabled = false;
            _hint.Visible = false;
            _progress.Visible = true;
            UseWaitCursor = true;

            ThreadPool.QueueUserWorkItem(delegate(object state)
            {
                // 后台: 端口发现 + 逐端口协议握手
                List<PortInfo> ports = PortDiscovery.GetListeningPortInfos(proc);
                List<int> portList = new List<int>();
                List<string> protoList = new List<string>();
                List<string> ownerList = new List<string>();
                foreach (PortInfo pi in ports)
                {
                    string proto = ProtocolProbe.Identify("127.0.0.1", pi.port, 800);
                    portList.Add(pi.port); protoList.Add(proto); ownerList.Add(pi.owner);
                }
                try
                {
                    BeginInvoke((MethodInvoker)delegate
                    {
                        if (IsDisposed) return;
                        _progress.Visible = false;
                        _hint.Visible = true;
                        UseWaitCursor = false;
                        _scanBtn.Enabled = true;
                        _okBtn.Enabled = true;
                        _candList.Items.Clear();
                        _portMap.Clear(); _protoMap.Clear();
                        if (portList.Count == 0)
                        {
                            _candList.Items.Add("未找到该进程监听的端口 (客户端未运行?)", false);
                            return;
                        }
                        for (int i = 0; i < portList.Count; i++)
                        {
                            int pt = portList[i]; string proto = protoList[i]; string owner = ownerList[i];
                            string label = pt + "  —  " + (proto == "UNKNOWN" ? "非代理端口" : proto + " 代理")
                                         + "  [" + owner + "]";
                            _candList.Items.Add(label, false);
                            _portMap[label] = pt; _protoMap[label] = proto;
                        }
                        Logger.Log("端口扫描[" + proc + "]: " + _candList.Items.Count + " 个候选, 其中代理端口 "
                                   + CountProxyPorts(portList, protoList));
                        if (_nameBox.Text.Length == 0) _nameBox.Text = proc;
                    });
                }
                catch (ObjectDisposedException) { }
                catch (InvalidOperationException) { }
            });
        }

        private Dictionary<string, int> _portMap = new Dictionary<string, int>();
        private Dictionary<string, string> _protoMap = new Dictionary<string, string>();

        private static string CountProxyPorts(List<int> ports, List<string> protos)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < ports.Count; i++)
            {
                if (protos[i] == "UNKNOWN") continue;
                if (sb.Length > 0) sb.Append(", ");
                sb.Append(ports[i] + "/" + protos[i]);
            }
            return sb.Length > 0 ? sb.ToString() : "(无)";
        }

        private void OnOk(object sender, EventArgs e)
        {
            foreach (object item in _candList.CheckedItems)
            {
                string label = item.ToString();
                int port; string proto;
                if (_portMap.TryGetValue(label, out port) && _protoMap.TryGetValue(label, out proto))
                {
                    if (proto == "UNKNOWN") continue;
                    ProxyEntry pe = new ProxyEntry();
                    pe.name = (_nameBox.Text.Trim().Length > 0 ? _nameBox.Text.Trim() : _procBox.Text.Trim()) + "-" + port;
                    pe.processName = _procBox.Text.Trim();
                    pe.host = "127.0.0.1";
                    pe.port = port;
                    pe.protocol = proto;
                    Added.Add(pe);
                }
            }
            if (Added.Count == 0) { MessageBox.Show("请至少勾选一个识别为代理的端口"); return; }
            DialogResult = DialogResult.OK;
            Close();
        }
    }

    // ============================ 主窗体 ============================
    public class MainForm : Form
    {
        private Engine _engine;
        private AppConfig _cfg;
        private ListView _lv;
        private Button _addBtn, _delBtn, _rescanBtn, _testBtn, _pauseBtn, _switchBtn;
        private NumericUpDown _intervalNum, _thresholdNum, _dwellNum;
        private Button _saveBtn;
        private StatusStrip _status;
        private ToolStripStatusLabel _stCurrent, _stNext, _stDecision, _stSys;
        private NotifyIcon _tray;
        private System.Windows.Forms.Timer _uiTimer;
        private bool _reallyExit = false;

        public MainForm()
        {
            // 启动清障: 删除 stop 标志 (看门狗依据)
            try { Directory.CreateDirectory(ConfigStore.RuntimeDir); File.Delete(Path.Combine(ConfigStore.RuntimeDir, "stop.flag")); } catch { }

            _cfg = ConfigStore.Load();
            _engine = new Engine(_cfg);
            _engine.Start();

            Text = "ProxyDirector — 本地多代理自动择优";
            ClientSize = new Size(880, 540);
            StartPosition = FormStartPosition.CenterScreen;
            Icon = SystemIcons.Application;

            BuildUi();
            BuildTray();

            _uiTimer = new System.Windows.Forms.Timer();
            _uiTimer.Interval = 1000;
            _uiTimer.Tick += OnUiTick;
            _uiTimer.Start();

            Logger.Log("ProxyDirector 启动");
        }

        private void BuildUi()
        {
            _lv = new ListView();
            _lv.View = View.Details; _lv.FullRowSelect = true; _lv.GridLines = true;
            _lv.Location = new Point(12, 12); _lv.Size = new Size(856, 300);
            _lv.Columns.Add("生效", 44);
            _lv.Columns.Add("名称", 140);
            _lv.Columns.Add("地址", 120);
            _lv.Columns.Add("协议", 60);
            _lv.Columns.Add("延迟", 70);
            _lv.Columns.Add("状态", 90);
            _lv.Columns.Add("详情", 250);
            _lv.Columns.Add("进程", 100);
            Controls.Add(_lv);

            _addBtn = MkBtn("添加代理", 12, 322, OnAdd);
            _delBtn = MkBtn("删除所选", 112, 322, OnDel);
            _rescanBtn = MkBtn("重新扫描端口", 212, 322, OnRescan);
            _testBtn = MkBtn("立即测速", 332, 322, OnTestNow);
            _switchBtn = MkBtn("手动切到此行", 432, 322, OnManualSwitch);
            _pauseBtn = MkBtn("暂停自动切换", 552, 322, OnPauseToggle);

            Label s1 = new Label(); s1.Text = "周期(秒)"; s1.AutoSize = true; s1.Location = new Point(12, 366); Controls.Add(s1);
            _intervalNum = new NumericUpDown(); _intervalNum.Location = new Point(80, 362); _intervalNum.Width = 70;
            _intervalNum.Minimum = 15; _intervalNum.Maximum = 3600; Controls.Add(_intervalNum);

            Label s2 = new Label(); s2.Text = "阈值(%)"; s2.AutoSize = true; s2.Location = new Point(170, 366); Controls.Add(s2);
            _thresholdNum = new NumericUpDown(); _thresholdNum.Location = new Point(230, 362); _thresholdNum.Width = 60;
            _thresholdNum.Minimum = 5; _thresholdNum.Maximum = 90; Controls.Add(_thresholdNum);

            Label s3 = new Label(); s3.Text = "停留(分)"; s3.AutoSize = true; s3.Location = new Point(310, 366); Controls.Add(s3);
            _dwellNum = new NumericUpDown(); _dwellNum.Location = new Point(375, 362); _dwellNum.Width = 60;
            _dwellNum.Minimum = 1; _dwellNum.Maximum = 120; Controls.Add(_dwellNum);

            _saveBtn = MkBtn("保存设置", 460, 360, OnSaveSettings);
            MkBtn("打开日志", 560, 360, OnOpenLog);

            Label note = new Label();
            note.Text = "使用前提: 关闭各代理客户端的\"系统代理\"开关, 由本工具独占管理系统代理。\n关闭窗口 = 最小化到托盘; 退出请用托盘图标右键 -> 退出。";
            note.ForeColor = Color.DimGray; note.AutoSize = true; note.Location = new Point(12, 396);
            Controls.Add(note);

            _status = new StatusStrip();
            _stCurrent = new ToolStripStatusLabel("当前: -");
            _stNext = new ToolStripStatusLabel("下轮: -");
            _stDecision = new ToolStripStatusLabel("决策: -");
            _stSys = new ToolStripStatusLabel("系统代理: -");
            _status.Items.Add(_stCurrent); _status.Items.Add(_stNext);
            _status.Items.Add(_stDecision); _status.Items.Add(_stSys);
            Controls.Add(_status);

            // 初始填充设置
            _intervalNum.Value = ClampNum(_cfg.checkIntervalSeconds, 15, 3600);
            _thresholdNum.Value = ClampNum(_cfg.switchThresholdPercent, 5, 90);
            _dwellNum.Value = ClampNum(_cfg.minDwellMinutes, 1, 120);
            _pauseBtn.Text = _cfg.autoSwitch ? "暂停自动切换" : "恢复自动切换";
        }

        private Button MkBtn(string text, int x, int y, EventHandler onClick)
        {
            Button b = new Button();
            b.Text = text; b.Location = new Point(x, y); b.Size = new Size(100, 30);
            b.Click += onClick;
            Controls.Add(b);
            return b;
        }

        private static decimal ClampNum(int v, int min, int max)
        {
            if (v < min) return min; if (v > max) return max; return v;
        }

        private void BuildTray()
        {
            _tray = new NotifyIcon();
            _tray.Icon = SystemIcons.Application;
            _tray.Text = "ProxyDirector";
            _tray.Visible = true;
            MenuItem showItem = new MenuItem("显示主窗口", delegate(object s, EventArgs e) { Show(); Activate(); });
            MenuItem exitItem = new MenuItem("退出", delegate(object s, EventArgs e) { _reallyExit = true; Close(); });
            _tray.ContextMenu = new ContextMenu(new MenuItem[] { showItem, exitItem });
            _tray.DoubleClick += delegate(object s, EventArgs e) { Show(); Activate(); };
        }

        private void OnUiTick(object sender, EventArgs e)
        {
            EngineSnapshot s = _engine.Snapshot;

            _lv.BeginUpdate();
            // 行集合只在代理增删/顺序变化时重建; 每秒仅原地更新单元格, 保留选中/焦点/滚动状态
            bool rebuild = _lv.Items.Count != s.states.Count;
            if (!rebuild)
            {
                for (int i = 0; i < s.states.Count; i++)
                {
                    if ((string)_lv.Items[i].Tag != s.states[i].cfg.name) { rebuild = true; break; }
                }
            }
            if (rebuild)
            {
                _lv.Items.Clear();
                foreach (ProxyState st in s.states)
                {
                    ListViewItem it = new ListViewItem();
                    it.Tag = st.cfg.name;
                    for (int k = 0; k < 7; k++) it.SubItems.Add("");
                    _lv.Items.Add(it);
                }
            }

            for (int i = 0; i < s.states.Count; i++)
            {
                ListViewItem it = _lv.Items[i];
                ProxyState st = s.states[i];
                bool isCur = st.cfg.name == s.currentName;
                it.SubItems[0].Text = isCur ? "●" : "";
                it.SubItems[1].Text = st.cfg.name;
                it.SubItems[2].Text = st.cfg.host + ":" + st.cfg.port;
                it.SubItems[3].Text = st.cfg.protocol;
                it.SubItems[4].Text = st.linkOk ? st.latencyMs + " ms" : "-";
                it.SubItems[5].Text = st.linkOk ? "可用" : "不可用";
                it.SubItems[6].Text = st.detail;
                it.SubItems[7].Text = st.cfg.processName;
                it.BackColor = isCur ? Color.FromArgb(220, 240, 220) : SystemColors.Window;
                it.ForeColor = st.linkOk ? SystemColors.WindowText : Color.Firebrick;
            }
            _lv.EndUpdate();

            _stCurrent.Text = "当前: " + (s.currentName.Length > 0 ? s.currentName : "(无)");
            _stNext.Text = "下轮: " + s.secondsToNext + "s";
            _stDecision.Text = "决策: " + (s.lastDecision.Length > 0 ? s.lastDecision : "-");
            _stSys.Text = "系统代理: " + s.sysProxy + (s.autoSwitch ? "  [自动]" : "  [暂停]");
            _pauseBtn.Text = s.autoSwitch ? "暂停自动切换" : "恢复自动切换";

            if (s.externalConflict.Length > 0)
                _stDecision.Text = "⚠ " + s.externalConflict;
        }

        private void OnAdd(object sender, EventArgs e)
        {
            using (AddProxyForm f = new AddProxyForm())
            {
                if (f.ShowDialog(this) == DialogResult.OK && f.Added.Count > 0)
                {
                    foreach (ProxyEntry pe in f.Added)
                    {
                        bool dup = false;
                        foreach (ProxyEntry old in _cfg.proxies)
                            if (old.port == pe.port && old.host == pe.host) { dup = true; break; }
                        if (!dup)
                        {
                            _cfg.proxies.Add(pe);
                            Logger.Log("用户添加代理: " + pe.name + " (" + pe.host + ":" + pe.port + " " + pe.protocol
                                       + ", 进程=" + pe.processName + ")");
                        }
                        else Logger.Log("用户添加代理 " + pe.name + ": 端口已存在, 跳过");
                    }
                    ConfigStore.Save(_cfg);
                    _engine.ReloadConfig();
                    _engine.ForceCheck();
                }
            }
        }

        private void OnDel(object sender, EventArgs e)
        {
            if (_lv.SelectedItems.Count == 0) { MessageBox.Show("请先选中一行"); return; }
            string name = _lv.SelectedItems[0].SubItems[1].Text;
            ProxyEntry dead = null;
            foreach (ProxyEntry p in _cfg.proxies) if (p.name == name) { dead = p; break; }
            if (dead != null)
            {
                _cfg.proxies.Remove(dead);
                ConfigStore.Save(_cfg);
                _engine.ReloadConfig();
                Logger.Log("用户删除代理: " + name);
            }
        }

        private void OnRescan(object sender, EventArgs e)
        {
            Logger.Log("用户触发重新扫描端口");
            _engine.RescanAll();
            MessageBox.Show("重新扫描完成, 结果见日志与列表");
        }

        private void OnTestNow(object sender, EventArgs e)
        {
            Logger.Log("用户触发立即测速");
            _engine.ForceCheck();
        }

        private void OnManualSwitch(object sender, EventArgs e)
        {
            if (_lv.SelectedItems.Count == 0) { MessageBox.Show("请先选中一行"); return; }
            string name = _lv.SelectedItems[0].SubItems[1].Text;
            _engine.ManualSwitch(name);
            _engine.ForceCheck();
        }

        private void OnPauseToggle(object sender, EventArgs e)
        {
            EngineSnapshot s = _engine.Snapshot;
            _engine.SetAutoSwitch(!s.autoSwitch);
        }

        private void OnSaveSettings(object sender, EventArgs e)
        {
            _engine.UpdateSettings((int)_intervalNum.Value, (int)_thresholdNum.Value, (int)_dwellNum.Value);
            Logger.Log("用户保存设置: 周期=" + (int)_intervalNum.Value + "s 阈值="
                       + (int)_thresholdNum.Value + "% 停留=" + (int)_dwellNum.Value + "分");
            MessageBox.Show("设置已保存");
        }

        private void OnOpenLog(object sender, EventArgs e)
        {
            try { Process.Start("notepad.exe", ConfigStore.LogPath); }
            catch (Exception ex) { MessageBox.Show("打开日志失败: " + ex.Message); }
        }

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            base.OnFormClosing(e);
            if (!_reallyExit)
            {
                e.Cancel = true;
                Hide();
                return;
            }
            // 退出: 写 stop 标志, 看门狗不再拉起
            try { File.WriteAllText(Path.Combine(ConfigStore.RuntimeDir, "stop.flag"), DateTime.Now.ToString()); } catch { }
            _tray.Visible = false;
            _engine.Stop();
            Logger.Log("ProxyDirector 退出");
        }
    }

    // ============================ 入口 ============================
    public static class Program
    {
        [STAThread]
        public static void Main(string[] args)
        {
            if (args != null && args.Length >= 2 && args[0] == "--console")
            {
                RunConsole(args);
                return;
            }
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
        }

        // 命令行自检: --console scan <进程名> | --console speed | --console decide
        private static void RunConsole(string[] args)
        {
            StringBuilder sb = new StringBuilder();
            try
            {
                if (args[1] == "scan" && args.Length >= 3)
                {
                    string proc = args[2];
                    sb.AppendLine("进程前缀 " + proc + " 监听的端口:");
                    List<PortInfo> ports = PortDiscovery.GetListeningPortInfos(proc);
                    if (ports.Count == 0) sb.AppendLine("  (无 - 进程未运行或无监听)");
                    foreach (PortInfo pi in ports)
                    {
                        string proto = ProtocolProbe.Identify("127.0.0.1", pi.port, 1000);
                        sb.AppendLine("  " + pi.port + "  -> " + (proto == "UNKNOWN" ? "非代理端口" : proto + " 代理")
                                      + "  [" + pi.owner + "]");
                    }
                }
                else if (args[1] == "speed" || args[1] == "decide")
                {
                    AppConfig cfg = ConfigStore.Load();
                    sb.AppendLine("配置代理数: " + cfg.proxies.Count + ", autoSwitch=" + cfg.autoSwitch);
                    List<ProxyState> states = new List<ProxyState>();
                    foreach (ProxyEntry p in cfg.proxies)
                    {
                        SpeedResult r = SpeedTester.Test(p.host, p.port, cfg);
                        ProxyState st = new ProxyState();
                        st.cfg = p; st.linkOk = r.ok; st.latencyMs = r.latencyMs;
                        st.detail = r.ok ? r.latencyMs + "ms" : "不可用";
                        states.Add(st);
                        sb.AppendLine("  " + p.name + " (" + p.host + ":" + p.port + ") -> " + st.detail);
                    }
                    if (args[1] == "decide")
                    {
                        string cur = SystemProxy.GetCurrent();
                        sb.AppendLine("当前系统代理: " + cur);
                        Dictionary<string, int> streak = new Dictionary<string, int>();
                        Decision d = DecisionMaker.Decide(states, cfg, "", DateTime.MinValue, streak);
                        sb.AppendLine("决策(dry-run): " + d.type + " " + d.targetName + " | " + d.reason);
                        sb.AppendLine("(dry-run 不写注册表)");
                    }
                }
                else sb.AppendLine("未知子命令: " + args[1]);
            }
            catch (Exception ex) { sb.AppendLine("异常: " + ex); }

            string outPath = Path.Combine(ConfigStore.BaseDir, "console-out.txt");
            File.WriteAllText(outPath, sb.ToString());
            // 尝试借父控制台输出
            try { Console.OutputEncoding = Encoding.UTF8; Console.Write(sb.ToString()); } catch { }
        }
    }
}
