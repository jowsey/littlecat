using littlecat.Server;
using littlecat.Utils;

namespace littlecat.Packets.Handlers.Login;

[PacketHandler(ClientState.Login, (int)PacketIds.Serverbound.Login.LoginStart)]
public class LoginStart : IPacketHandler
{
    public Task HandlePacket(Server.Server server, MinecraftClient client)
    {
        Console.WriteLine("Got login start.");

        var name = client.GetStream().ReadString();
        var uuid = client.GetStream().ReadUuid();

        Console.WriteLine($"Player is {name} with UUID {uuid.ToString("X").ToLower()}");

        client.Username = name;
        client.Uuid = uuid;

        // Encryption request
        client.VerifyToken = new byte[4];
        Random.Shared.NextBytes(client.VerifyToken);

        var encryptionRequestPacket = new PacketBuilder((int)PacketIds.Clientbound.Login.EncryptionRequest)
            .AppendString("") // server id (unused?)
            .AppendLengthPrefixedBytes(server.PublicKey) // public key
            .AppendLengthPrefixedBytes(client.VerifyToken) // verify token
            .AppendBoolean(true); // should authenticate

        client.GetStream().Write(encryptionRequestPacket.Build());
        Console.WriteLine("Sent encryption request.");

        return Task.CompletedTask;
    }
}