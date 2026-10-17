using System.Text.Json;

namespace Suhang.Desktop;

internal enum DeviceConnectionState { Offline, Connected, Connecting, Error }

// Connected controls traffic lifetime; ConnectionState controls the connection badge.
// They remain separate because a transport can exist before peer verification succeeds.
internal sealed record DeviceStatus
{
    internal static readonly DeviceStatus Missing = new();
    internal bool IsPresent { get; init; }
    internal bool Connected { get; init; }
    internal DeviceConnectionState ConnectionState { get; init; }
    internal string Title { get; init; } = "";
    internal string Subtitle { get; init; } = "";
    internal string Health { get; init; } = "";
    internal string PeerIPv4 { get; init; } = "";
    internal string PeerAddressState { get; init; } = "";
    internal bool RetryAvailable { get; init; }
    internal double Tx { get; init; }
    internal double Rx { get; init; }
    internal string Speed { get; init; } = "";
    internal string Latency { get; init; } = "";
    internal bool MeasurementBusy { get; init; }
    internal double MeasurementProgress { get; init; }
    internal string BenchmarkURL { get; init; } = "";
    internal string BenchmarkSummary { get; init; } = "";

    internal static DeviceStatus Parse(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.Object) return Missing;
        var connected = Flag(value, "connected");
        var state = Text(value, "connection_state");
        return new()
        {
            IsPresent = true,
            Connected = connected,
            ConnectionState = state switch
            {
                "connected" => DeviceConnectionState.Connected,
                "connecting" => DeviceConnectionState.Connecting,
                "error" => DeviceConnectionState.Error,
                "" when connected => DeviceConnectionState.Connected,
                _ => DeviceConnectionState.Offline,
            },
            Title = Text(value, "title"), Subtitle = Text(value, "subtitle"), Health = Text(value, "health"),
            PeerIPv4 = Text(value, "peer_ipv4"), PeerAddressState = Text(value, "peer_address_state"),
            RetryAvailable = Flag(value, "retry_available"), Tx = Number(value, "tx"), Rx = Number(value, "rx"),
            Speed = Text(value, "speed"), Latency = Text(value, "latency"),
            MeasurementBusy = Flag(value, "measurement_busy"), MeasurementProgress = Number(value, "measurement_progress"),
            BenchmarkURL = Text(value, "benchmark_url"), BenchmarkSummary = Text(value, "benchmark_summary"),
        };
    }

    internal static string Text(JsonElement value, string key) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var field) && field.ValueKind == JsonValueKind.String ? field.GetString() ?? "" : "";
    internal static bool Flag(JsonElement value, string key) =>
        value.ValueKind == JsonValueKind.Object && value.TryGetProperty(key, out var field) && field.ValueKind == JsonValueKind.True;
    static double Number(JsonElement value, string key) =>
        value.TryGetProperty(key, out var field) && field.ValueKind == JsonValueKind.Number && field.TryGetDouble(out var number) && double.IsFinite(number) ? number : 0;
}

internal sealed record DeviceStatusSnapshot(DeviceStatus Mac, DeviceStatus IPad, int ConnectedCount, int ConnectingCount, bool HasError)
{
    internal static DeviceStatusSnapshot Parse(JsonElement display)
    {
        var mac = DeviceStatus.Missing;
        var ipad = DeviceStatus.Missing;
        var connected = 0; var connecting = 0; var error = false;
        if (display.ValueKind == JsonValueKind.Object && display.TryGetProperty("devices", out var devices) && devices.ValueKind == JsonValueKind.Array)
        {
            foreach (var slot in devices.EnumerateArray())
            {
                var kind = DeviceStatus.Text(slot, "device");
                if (kind != "Mac" && kind != "iPad") continue;
                var status = DeviceStatus.Parse(slot);
                if (kind == "Mac") mac = status; else ipad = status;
                switch (status.ConnectionState)
                {
                    case DeviceConnectionState.Connected: connected++; break;
                    case DeviceConnectionState.Connecting: connecting++; break;
                    case DeviceConnectionState.Error: error = true; break;
                }
            }
        }
        else
        {
            // Older cores send a single snapshot and summarize it by the connected flag.
            var status = DeviceStatus.Parse(display);
            if (DeviceStatus.Text(display, "device") == "iPad") ipad = status; else mac = status;
            connected = status.Connected ? 1 : 0;
        }
        return new(mac, ipad, connected, connecting, error);
    }
}
