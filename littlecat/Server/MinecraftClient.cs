using System.Net.Sockets;
using Org.BouncyCastle.Crypto.IO;

namespace littlecat.Server;

public enum ClientState
{
    Handshake,
    Status,
    Login,
    Transfer,
    Configuration,
    Play
}

public class MinecraftClient(TcpClient tcpClient) : IDisposable
{
    public TcpClient TcpClient { get; } = tcpClient;

    // Encryption
    public bool EncryptionEnabled = false;
    public byte[] VerifyToken = [];
    public CipherStream? EncryptedStream = null;

    public ClientState ClientState = ClientState.Handshake;

    // Login
    public string? Username;
    public UInt128? Uuid;

    public Stream GetStream() => EncryptionEnabled ? EncryptedStream! : TcpClient.GetStream();

    // Close the connection
    public void Dispose()
    {
        EncryptedStream?.Dispose();
        TcpClient.Dispose();
        GC.SuppressFinalize(this);
    }
}