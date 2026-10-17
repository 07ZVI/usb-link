using System.Text.Json;

namespace Suhang.Desktop;

// Runs without an Avalonia window, including on CI hosts without a desktop session.
internal static class DeviceStatusSmoke
{
    internal static int Run(string[] args)
    {
        try
        {
            var paths = args.SkipWhile(arg => arg != "--device-status-smoke").Skip(1).ToArray();
            if (paths.Length == 0) throw new InvalidOperationException("Pass one or more device-status fixture paths.");
            var count = 0;
            foreach (var path in paths)
            {
                using var fixtures = JsonDocument.Parse(File.ReadAllText(path));
                foreach (var fixture in fixtures.RootElement.EnumerateArray())
                {
                    var name = fixture.GetProperty("name").GetString() ?? path;
                    var actual = DeviceStatusSnapshot.Parse(fixture.GetProperty("payload"));
                    var expected = fixture.GetProperty("expected");
                    Check(actual.ConnectedCount == expected.GetProperty("connected").GetInt32(), name + ": connected count");
                    Check(actual.ConnectingCount == expected.GetProperty("connecting").GetInt32(), name + ": connecting count");
                    Check(actual.HasError == expected.GetProperty("error").GetBoolean(), name + ": error summary");
                    CheckDevice(actual.Mac, expected.GetProperty("mac"), name + ": Mac");
                    CheckDevice(actual.IPad, expected.GetProperty("ipad"), name + ": iPad");
                    count++;
                }
            }
            Console.Error.WriteLine($"DEVICE_STATUS_SMOKE_PASS: {count} fixtures");
            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine("DEVICE_STATUS_SMOKE_FAIL: " + error);
            return 1;
        }
    }

    static void CheckDevice(DeviceStatus actual, JsonElement expected, string name)
    {
        Check(actual.IsPresent == expected.GetProperty("present").GetBoolean(), name + ": presence");
        Check(actual.Connected == expected.GetProperty("connected").GetBoolean(), name + ": connected flag");
        Check(actual.ConnectionState.ToString().ToLowerInvariant() == expected.GetProperty("state").GetString(), name + ": connection state");
        Check(actual.PeerIPv4 == expected.GetProperty("peer_ipv4").GetString(), name + ": peer address");
        Check(actual.Tx == expected.GetProperty("tx").GetDouble(), name + ": transmit rate");
        Check(actual.Rx == expected.GetProperty("rx").GetDouble(), name + ": receive rate");
        Check(actual.RetryAvailable == expected.GetProperty("retry_available").GetBoolean(), name + ": retry availability");
        Check(actual.BenchmarkURL == expected.GetProperty("benchmark_url").GetString(), name + ": benchmark URL");
        foreach (var field in expected.EnumerateObject())
        {
            var text = field.Name switch
            {
                "title" => actual.Title, "subtitle" => actual.Subtitle, "health" => actual.Health,
                "peer_address_state" => actual.PeerAddressState, "speed" => actual.Speed,
                "latency" => actual.Latency, "benchmark_summary" => actual.BenchmarkSummary,
                _ => null,
            };
            if (text != null) Check(text == field.Value.GetString(), name + ": " + field.Name);
        }
        if (expected.TryGetProperty("measurement_busy", out var busy)) Check(actual.MeasurementBusy == busy.GetBoolean(), name + ": measurement busy");
        if (expected.TryGetProperty("measurement_progress", out var progress)) Check(actual.MeasurementProgress == progress.GetDouble(), name + ": measurement progress");
    }

    static void Check(bool valid, string message)
    {
        if (!valid) throw new InvalidOperationException(message);
    }
}
