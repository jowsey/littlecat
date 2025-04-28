using System.Globalization;
using System.Security.Cryptography;
using littlecat.Server;
using littlecat.Utils;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace littlecat.Packets.Handlers.Login;

[PacketHandler(ClientState.Login, (int)PacketIds.Serverbound.Login.EncryptionResponse)]
public class EncryptionResponse : IPacketHandler
{
    public async Task HandlePacket(Server.Server server, MinecraftClient client)
    {
        Console.WriteLine("Got encryption response.");

        var stream = client.GetStream();
        var sharedSecret = stream.ReadLengthPrefixedBytes();
        var verifyToken = stream.ReadLengthPrefixedBytes();

        // Decrypt both using our RSA private key
        using var rsa = RSA.Create();
        rsa.ImportParameters(server.PrivateKey);

        var decryptedSharedSecret = rsa.Decrypt(sharedSecret, RSAEncryptionPadding.Pkcs1);
        var decryptedVerifyToken = rsa.Decrypt(verifyToken, RSAEncryptionPadding.Pkcs1);

        Console.WriteLine("  Our verify token: " + Convert.ToHexString(client.VerifyToken));
        Console.WriteLine("Their verify token: " + Convert.ToHexString(decryptedVerifyToken));

        if (!decryptedVerifyToken.SequenceEqual(client.VerifyToken))
        {
            Console.WriteLine("Invalid verify token! Closing connection.");
            client.Close();
            return;
        }

        Console.WriteLine("Validated verify token.");

        var key = new KeyParameter(decryptedSharedSecret);
        var parameters = new ParametersWithIV(key, decryptedSharedSecret);

        var aesEngine = new AesEngine();
        var aesEncrypt = new BufferedBlockCipher(new CfbBlockCipher(aesEngine, 8));
        aesEncrypt.Init(true, parameters);

        var aesDecrypt = new BufferedBlockCipher(new CfbBlockCipher(aesEngine, 8));
        aesDecrypt.Init(false, parameters);

        client.EncryptedStream = new CipherStream(client.GetStream(), aesDecrypt, aesEncrypt);
        client.EncryptionEnabled = true;

        Console.WriteLine("Enabled encryption.");

        var url = $"https://sessionserver.mojang.com/session/minecraft/hasJoined" +
                  $"?username={client.Username}" +
                  $"&serverId={decryptedSharedSecret.Concat(server.PublicKey).ToMinecraftSha1HexDigest()}";
        // $"&ip={(client.TcpClient.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString()}";

        Console.WriteLine($"Connecting to {url}...");

        var request = await server.HttpClient.GetAsync(url);
        request.EnsureSuccessStatusCode();

        var response = await request.Content.ReadAsStringAsync();
        var json = JObject.Parse(response);

        var name = json["name"]?.Value<string>()!;
        var uuid = json["id"]?.Value<string>()!;
        var properties = json["properties"]!;
        Console.WriteLine($"Got name {name} and UUID {uuid} from Mojang.");

        var packet = new PacketBuilder((int)PacketIds.Clientbound.Login.LoginSuccess)
            .AppendUuid(UInt128.Parse(uuid, NumberStyles.HexNumber))
            .AppendString(name);

        var propertyCount = properties.Count();
        packet.AppendVarInt(propertyCount);
        foreach (var property in properties)
        {
            packet.AppendString(property["name"]!.ToString());
            packet.AppendString(property["value"]!.ToString());
            packet.AppendBoolean(true);
            packet.AppendString(property["signature"]!.ToString()); // todo don't blindly assume we'll receive all this lol
        }

        client.GetStream().Write(packet.Build());

        Console.WriteLine("Sent login success.");
    }
}