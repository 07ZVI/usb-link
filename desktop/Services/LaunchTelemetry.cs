namespace Suhang.Desktop;

// Bounded, fixed display-only startup markers. The parent measures arrival on
// its monotonic clock and binds them to this owned renderer's actual launch.
// Avoid reflection/JSON serializer initialization in the critical ready path.
internal static class LaunchTelemetry
{
    public static void Mark(string stage)
    {
        if (Program.Preview) return;
        try
        {
            DesktopClient.SendRaw("{\"action\":\"renderer-stage\",\"id\":\"" + stage + "\"}");
            
        }
        catch (IOException) { /* Measurement failure never changes window lifetime. */ }
        catch (ObjectDisposedException) { /* Closing a pipe cannot keep the window alive. */ }
    }
}
