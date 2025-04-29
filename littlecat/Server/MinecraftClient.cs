using System.Net.Sockets;
using littlecat.Packets;
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

    public void SendPluginMessage(string channel, byte[] data)
    {
        var stream = GetStream();
        var packet = new PacketBuilder((int)PacketIds.Clientbound.Configuration.PluginMessage)
            .AppendString(channel)
            .AppendBytes(data);
        stream.Write(packet.Build());
    }

    // Close the connection
    public void Dispose()
    {
        EncryptedStream?.Dispose();
        TcpClient.Dispose();
        GC.SuppressFinalize(this);
    }
}