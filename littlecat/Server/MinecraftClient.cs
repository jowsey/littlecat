using System.Net.Sockets;

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

public class MinecraftClient(TcpClient client)
{
    public ClientState ClientState = ClientState.Handshake;

    public NetworkStream GetStream() => client.GetStream();
    public void Close() => client.Close();
}