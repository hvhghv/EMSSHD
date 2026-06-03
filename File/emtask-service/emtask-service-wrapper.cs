using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.ServiceProcess;
using System.Text;

public sealed class EmtaskWindowsService : ServiceBase
{
    private readonly string configFile;
    private readonly object writerLock = new object();
    private Process child;
    private StreamWriter stdoutWriter;
    private StreamWriter stderrWriter;
    private string pidFile;
    private volatile bool stopping;

    public EmtaskWindowsService(string serviceName, string configFile)
    {
        this.ServiceName = serviceName;
        this.configFile = configFile;
        this.CanStop = true;
        this.CanShutdown = true;
        this.AutoLog = true;
    }

    public static int Main(string[] args)
    {
        string serviceName = "emtask";
        string configFile = null;

        for (int i = 0; i < args.Length; ++i)
        {
            if (String.Equals(args[i], "--service", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                serviceName = args[++i];
            }
            else if (String.Equals(args[i], "--config", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
            {
                configFile = args[++i];
            }
        }

        if (String.IsNullOrEmpty(configFile))
        {
            return 2;
        }

        ServiceBase.Run(new EmtaskWindowsService(serviceName, configFile));
        return 0;
    }

    protected override void OnStart(string[] args)
    {
        this.stopping = false;
        StartEmtask();
    }

    protected override void OnStop()
    {
        this.stopping = true;
        StopEmtask();
    }

    protected override void OnShutdown()
    {
        this.stopping = true;
        StopEmtask();
        base.OnShutdown();
    }

    private void StartEmtask()
    {
        Dictionary<string, string> cfg = ReadConfig(this.configFile);
        string exePath = Required(cfg, "emtaskExe");
        string emtaskConfig = Required(cfg, "emtaskConfig");
        string workingDirectory = Required(cfg, "workingDirectory");
        string logDirectory = Required(cfg, "logDirectory");

        Directory.CreateDirectory(logDirectory);
        this.pidFile = Path.Combine(logDirectory, "emtask.pid");

        this.stdoutWriter = OpenLogWriter(Path.Combine(logDirectory, "emtask.stdout.log"));
        this.stderrWriter = OpenLogWriter(Path.Combine(logDirectory, "emtask.stderr.log"));

        ProcessStartInfo startInfo = new ProcessStartInfo();
        startInfo.FileName = exePath;
        startInfo.Arguments = "--config " + QuoteArgument(emtaskConfig);
        startInfo.WorkingDirectory = workingDirectory;
        startInfo.UseShellExecute = false;
        startInfo.CreateNoWindow = true;
        startInfo.RedirectStandardOutput = true;
        startInfo.RedirectStandardError = true;

        this.child = new Process();
        this.child.StartInfo = startInfo;
        this.child.EnableRaisingEvents = true;
        this.child.OutputDataReceived += OnStdout;
        this.child.ErrorDataReceived += OnStderr;
        this.child.Exited += OnChildExited;

        if (!this.child.Start())
        {
            throw new InvalidOperationException("Failed to start emtask process.");
        }

        File.WriteAllText(this.pidFile, this.child.Id.ToString(), Encoding.ASCII);
        this.child.BeginOutputReadLine();
        this.child.BeginErrorReadLine();
        WriteLine(this.stdoutWriter, "[service] emtask started, pid=" + this.child.Id.ToString());
    }

    private void StopEmtask()
    {
        Process process = this.child;
        if (process != null)
        {
            try
            {
                if (!process.HasExited)
                {
                    KillProcessTree(process.Id);
                    if (!process.WaitForExit(10000))
                    {
                        process.Kill();
                        process.WaitForExit(5000);
                    }
                }
            }
            catch
            {
            }
        }

        try
        {
            if (!String.IsNullOrEmpty(this.pidFile) && File.Exists(this.pidFile))
            {
                File.Delete(this.pidFile);
            }
        }
        catch
        {
        }

        CloseWriters();
    }

    private void OnChildExited(object sender, EventArgs eventArgs)
    {
        if (this.stopping)
        {
            return;
        }

        int exitCode = 1;
        try
        {
            exitCode = this.child != null ? this.child.ExitCode : 1;
        }
        catch
        {
        }

        WriteLine(this.stderrWriter, "[service] emtask exited unexpectedly, exitCode=" + exitCode.ToString());

        try
        {
            if (!String.IsNullOrEmpty(this.pidFile) && File.Exists(this.pidFile))
            {
                File.Delete(this.pidFile);
            }
        }
        catch
        {
        }

        Environment.Exit(exitCode == 0 ? 1 : exitCode);
    }

    private void OnStdout(object sender, DataReceivedEventArgs eventArgs)
    {
        if (eventArgs.Data != null)
        {
            WriteLine(this.stdoutWriter, eventArgs.Data);
        }
    }

    private void OnStderr(object sender, DataReceivedEventArgs eventArgs)
    {
        if (eventArgs.Data != null)
        {
            WriteLine(this.stderrWriter, eventArgs.Data);
        }
    }

    private void WriteLine(StreamWriter writer, string text)
    {
        lock (this.writerLock)
        {
            if (writer != null)
            {
                writer.WriteLine(text);
                writer.Flush();
            }
        }
    }

    private void CloseWriters()
    {
        lock (this.writerLock)
        {
            try
            {
                if (this.stdoutWriter != null)
                {
                    this.stdoutWriter.Dispose();
                    this.stdoutWriter = null;
                }
            }
            catch
            {
            }

            try
            {
                if (this.stderrWriter != null)
                {
                    this.stderrWriter.Dispose();
                    this.stderrWriter = null;
                }
            }
            catch
            {
            }
        }
    }

    private static StreamWriter OpenLogWriter(string path)
    {
        FileStream stream = new FileStream(path, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
        StreamWriter writer = new StreamWriter(stream, new UTF8Encoding(false));
        writer.AutoFlush = true;
        writer.WriteLine("[service] log opened at " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));
        return writer;
    }

    private static Dictionary<string, string> ReadConfig(string path)
    {
        Dictionary<string, string> values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string[] lines = File.ReadAllLines(path, Encoding.UTF8);

        for (int i = 0; i < lines.Length; ++i)
        {
            string line = lines[i].Trim();
            if (line.Length == 0 || line.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            int eq = line.IndexOf('=');
            if (eq <= 0)
            {
                continue;
            }

            string key = line.Substring(0, eq).Trim();
            string encoded = line.Substring(eq + 1).Trim();
            values[key] = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
        }

        return values;
    }

    private static string Required(Dictionary<string, string> values, string key)
    {
        string value;
        if (!values.TryGetValue(key, out value) || String.IsNullOrEmpty(value))
        {
            throw new InvalidOperationException("Missing service wrapper config key: " + key);
        }
        return value;
    }

    private static string QuoteArgument(string value)
    {
        if (value == null)
        {
            return "\"\"";
        }
        return "\"" + value.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";
    }

    private static void KillProcessTree(int pid)
    {
        try
        {
            ProcessStartInfo startInfo = new ProcessStartInfo();
            startInfo.FileName = "taskkill.exe";
            startInfo.Arguments = "/PID " + pid.ToString() + " /T /F";
            startInfo.UseShellExecute = false;
            startInfo.CreateNoWindow = true;
            Process killer = Process.Start(startInfo);
            if (killer != null)
            {
                killer.WaitForExit(10000);
                killer.Dispose();
            }
        }
        catch
        {
        }
    }
}
