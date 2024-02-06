using System.Drawing;
using Pastel;

namespace littlecat.Utils;

public static class ThreadLogger
{
    public static void Log(string message)
    {
        var threadId = Environment.CurrentManagedThreadId;
        Console.WriteLine($"[{(threadId == 1 ? "main" : threadId)}] {message}");
    }

    public static void Warn(string message)
    {
        Log($"[WARN] {message}".Pastel(Color.Coral));
    }
}