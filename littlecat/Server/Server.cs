using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using littlecat.Packets.Handlers;
using littlecat.Utils;

namespace littlecat.Server;

public static class PacketIds
{
    public static class Serverbound
    {
        public enum Handshake
        {
            Handshake = 0x00
        }

        public enum Status
        {
            StatusRequest = 0x00,
            PingRequest = 0x01
        }

        public enum Login
        {
            LoginStart = 0x00,
            EncryptionResponse = 0x01,
            LoginAcknowledged = 0x03
        }
    }

    public static class Clientbound
    {
        public enum Status
        {
            StatusResponse = 0x00,
            PongResponse = 0x01
        }

        public enum Login
        {
            EncryptionRequest = 0x01,
            LoginSuccess = 0x02
        }
    }
}

public class Server
{
    private readonly TcpListener _tcpListener = new(IPAddress.Any, 25565);
    private readonly Dictionary<(ClientState clientState, int packetId), IPacketHandler> _packetHandlers = new();

    public int MaxPlayers = 20;

    public byte[] PublicKey { get; }
    public RSAParameters PrivateKey { get; }

    public HttpClient HttpClient { get; } = new();

    public Server()
    {
        Console.WriteLine("Generating RSA keypair...");
        using var rsa = RSA.Create(1024);
        PublicKey = rsa.ExportSubjectPublicKeyInfo();
        PrivateKey = rsa.ExportParameters(true);

        // detect & register all packet handlers
        Console.WriteLine("Registering packet handlers for:");
        var assembly = Assembly.GetExecutingAssembly();
        var handlerTypes = assembly
            .GetTypes()
            .Where(t => t.IsAssignableTo(typeof(IPacketHandler)) && t.GetCustomAttribute<PacketHandlerAttribute>() != null)
            .OrderBy(t => t.GetCustomAttribute<PacketHandlerAttribute>()!.ClientState)
            .ThenBy(t => t.GetCustomAttribute<PacketHandlerAttribute>()!.PacketId)
            .ToList();

        var longestTypeName = handlerTypes.Max(t => t.Name.Length);
        foreach (var type in handlerTypes)
        {
            var attribute = type.GetCustomAttribute<PacketHandlerAttribute>();
            _packetHandlers.Add((attribute!.ClientState, attribute.PacketId), (IPacketHandler)Activator.CreateInstance(type)!);
            Console.WriteLine($" - {type.Name.PadRight(longestTypeName + 1)} 0x{attribute.PacketId:x2} @ {attribute.ClientState}");
        }

        Console.WriteLine();
    }

    public async void Start()
    {
        _tcpListener.Start();

        Console.WriteLine("Server started");

        while (_tcpListener.Server.IsBound)
        {
            var client = await _tcpListener.AcceptTcpClientAsync();
            Console.WriteLine("Client connected, passing to handler");

            var minecraftClient = new MinecraftClient(client);
            _ = Task.Run(() => HandleClient(minecraftClient));
        }
    }

    public void Stop()
    {
        _tcpListener.Stop();
        Console.WriteLine("Server stopped");
    }

    private void HandleClient(MinecraftClient client)
    {
        using var stream = client.GetStream();

        while (true)
        {
            var length = client.GetStream().ReadVarInt();
            var id = client.GetStream().ReadVarInt();

            Console.WriteLine($"[{client.ClientState}] Packet with id {id:x2} and length {length}");

            if (_packetHandlers.TryGetValue((client.ClientState, id), out var handler))
            {
                handler.HandlePacket(this, client);
            }
            else
            {
                Console.WriteLine("No handler registered! Discarding.");
                client.GetStream().ReadExactly(new byte[length], 0, length); // discard the packet so it doesn't affect the next one
            }
        }

        client.Close();
        Console.WriteLine("Client disconnected");
    }
}