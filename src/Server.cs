using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using littlecat.Extensions;
using littlecat.Packets;
using littlecat.Utils;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace littlecat;

public enum ClientboundPacketId
{
    StatusResponse = 0x00,
    PluginMessage = 0x01,
    PongResponse = 0x01,
    EncryptionRequest = 0x01,
    LoginSuccess = 0x02,
    FinishConfiguration = 0x03,
    FeatureFlags = 0x0C,
    KnownPacks = 0x0E,
    ChunkDataAndUpdateLight = 0x25,
    Play = 0x29
}

public enum ConnectionState
{
    Handshaking,
    Status,
    Login,
    Transfer, // todo not sure if needed
    Configuration,
    Play
}

public struct Pack
{
    public string Namespace;
    public string Id;
    public string Version;
}

public class Client
{
    public required NetworkStream Stream;
    public CipherStream? CipherStream;

    // State
    public ConnectionState State = ConnectionState.Handshaking;

    // Encryption
    public readonly byte[] VerifyToken = new byte[4];
    public bool EncryptionActive; // todo can't we just check if CipherStream is null?

    // User
    public string? Username;
    
    public readonly List<Pack> KnownPacks = new();
}

public class Server
{
    private const string Version = "1.21.1";
    private const int ProtocolVersion = 767;

    private readonly Config _configHandler;
    private readonly string? _faviconBase64;

    // Encryption
    private readonly byte[] _publicKeyDer;
    private readonly IBufferedCipher _rsaDecrypt;

    private BufferedBlockCipher? _aesEncrypt;
    private BufferedBlockCipher? _aesDecrypt;

    public Server(Config configHandler)
    {
        _configHandler = configHandler;

        // load favicon
        var serverDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)!;
        var faviconPath = Path.Combine(serverDir, _configHandler.FaviconPath);
        if (File.Exists(faviconPath))
        {
            var faviconBytes = File.ReadAllBytes(_configHandler.FaviconPath);
            _faviconBase64 = Convert.ToBase64String(faviconBytes);
        }

        // generate rsa keys
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
        var keyPair = generator.GenerateKeyPair();

        _rsaDecrypt = CipherUtilities.GetCipher("RSA/None/PKCS1Padding");
        _rsaDecrypt.Init(false, keyPair.Private);

        _publicKeyDer = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(keyPair.Public).GetDerEncoded();
    }

    public async Task StartServer()
    {
        var ipEndPoint = new IPEndPoint(IPAddress.Any, _configHandler.Port);
        var listener = new TcpListener(ipEndPoint);

        try
        {
            listener.Start();

            while (true)
            {
                Console.WriteLine("Waiting for a connection...");

                var client = await listener.AcceptTcpClientAsync();
                _ = Task.Run(() => HandleClientAsync(client));
            }
        }
        catch (SocketException e)
        {
            Console.WriteLine($"SocketException: {e}");
        }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleClientAsync(TcpClient tcpClient)
    {
        Console.WriteLine($"Connected to {tcpClient.Client.RemoteEndPoint}");

        var client = new Client
        {
            Stream = tcpClient.GetStream()
        };

        try
        {
            while (tcpClient.Connected)
            {
                Stream stream = client.EncryptionActive
                    ? client.CipherStream!
                    : client.Stream;

                var packetLength = stream.ReadVarInt();
                var packetId = stream.ReadVarInt(); // todo see error

                Console.WriteLine($"Recieved packet 0x{packetId:X} while in {client.State}, length {packetLength}");

                switch (packetId)
                {
                    case 0x00 when client.State == ConnectionState.Handshaking: // Handshake
                    {
                        Console.WriteLine("Handshake packet");

                        var protocolVersion = stream.ReadVarInt();
                        if (protocolVersion != ProtocolVersion)
                        {
                            Console.WriteLine(
                                $"Protocol version mismatch: expected {ProtocolVersion}, got {protocolVersion}");
                            tcpClient.Close();
                            break;
                        }

                        _ = stream.ReadString(); // server address (unused)
                        _ = stream.ReadShort(); // server port (unused)
                        var nextState = stream.ReadVarInt();
                        Console.WriteLine($"Next state: {nextState} ({(ConnectionState)nextState})");

                        client.State = (ConnectionState)nextState;
                        break;
                    }
                    case 0x00 when client.State == ConnectionState.Status: // Status request
                    {
                        Console.WriteLine("Status request packet");

                        JObject response = new()
                        {
                            ["version"] = new JObject
                            {
                                ["name"] = Version,
                                ["protocol"] = ProtocolVersion
                            },
                            ["players"] = new JObject
                            {
                                ["max"] = _configHandler.MaxPlayers,
                                ["online"] = 0,
                                // ["sample"] = new JArray
                                // {
                                //     new JObject
                                //     {
                                //         ["name"] = "Jowc",
                                //         ["id"] = "1658caaf-0db9-43eb-ae89-1c22900d37c3"
                                //     }
                                // }
                            },
                            ["description"] = new JObject
                            {
                                ["text"] = _configHandler.Motd
                            },
                            ["favicon"] = _faviconBase64 != null
                                ? "data:image/png;base64," + _faviconBase64
                                : null,
                            ["enforcesSecureChat"] = false,
                            ["previewsChat"] = false
                        };

                        SendPacket(client,
                            new PacketBuilder(ClientboundPacketId.StatusResponse)
                                .AppendString(JsonConvert.SerializeObject(response))
                        );

                        break;
                    }
                    case 0x01 when client.State == ConnectionState.Status: // Ping request
                    {
                        Console.WriteLine("Ping request packet");
                        var payload = stream.ReadLong();

                        SendPacket(client,
                            new PacketBuilder(ClientboundPacketId.PongResponse)
                                .AppendLong(payload)
                        );

                        tcpClient.Close();
                        break;
                    }
                    case 0x00 when client.State == ConnectionState.Login: // Login start
                    {
                        Console.WriteLine("Login start packet");

                        var playerName = stream.ReadString();
                        var playerUuid = stream.ReadUuid();

                        Console.WriteLine($"Player name: {playerName}");
                        Console.WriteLine($"Player UUID: {playerUuid}");

                        client.Username = playerName;

                        new Random().NextBytes(client.VerifyToken);

                        SendPacket(client,
                            new PacketBuilder(ClientboundPacketId.EncryptionRequest)
                                .AppendString("") // server id
                                .AppendLengthPrefixedByteArray(_publicKeyDer)
                                .AppendLengthPrefixedByteArray(client.VerifyToken)
                                .AppendBoolean(true)
                        );
                        break;
                    }
                    case 0x01 when client.State == ConnectionState.Login: // Encryption response
                    {
                        Console.WriteLine("Encryption response packet");

                        var sharedSecret = stream.ReadLengthPrefixedBytes();
                        var verifyToken = stream.ReadLengthPrefixedBytes();

                        var decryptedVerifyToken = _rsaDecrypt.DoFinal(verifyToken);
                        var decryptedSharedSecret = _rsaDecrypt.DoFinal(sharedSecret);

                        if (!client.VerifyToken.SequenceEqual(decryptedVerifyToken))
                        {
                            Console.WriteLine("Verify tokens do not match");
                            tcpClient.Close();
                            break;
                        }

                        Console.WriteLine("Verify tokens match");

                        var key = new KeyParameter(decryptedSharedSecret);
                        var iv = new ParametersWithIV(key, decryptedSharedSecret);

                        _aesEncrypt = new BufferedBlockCipher(new CfbBlockCipher(new AesEngine(), 8));
                        _aesEncrypt.Init(true, iv);

                        _aesDecrypt = new BufferedBlockCipher(new CfbBlockCipher(new AesEngine(), 8));
                        _aesDecrypt.Init(false, iv);

                        client.CipherStream = new CipherStream(client.Stream, _aesDecrypt, _aesEncrypt);
                        client.EncryptionActive = true;

                        var digest = decryptedSharedSecret.Concat(_publicKeyDer).ToMinecraftShaHexDigest();

                        var userInfo = await MojangApi.GetUserInfo(client.Username!, digest);
                        var uuid = userInfo["id"]?.ToObject<string>();
                        var username = userInfo["name"]?.ToObject<string>();
                        
                        var loginSuccessPacket = new PacketBuilder(ClientboundPacketId.LoginSuccess)
                            .AppendUuid(UInt128.Parse(uuid!, NumberStyles.HexNumber))
                            .AppendString(username!);

                        var numberOfProperties = userInfo["properties"]?.Count() ?? 0;
                        
                        loginSuccessPacket.AppendVarInt(numberOfProperties);

                        foreach (var property in userInfo["properties"]!)
                        {
                            loginSuccessPacket
                                .AppendString(property["name"]!.ToObject<string>()!)
                                .AppendString(property["value"]!.ToObject<string>()!);
                            
                            if (property["signature"] != null)
                            {
                                loginSuccessPacket
                                    .AppendBoolean(true)
                                    .AppendString(property["signature"]!.ToObject<string>()!);
                            }
                            else
                            {
                                loginSuccessPacket.AppendBoolean(false); // not signed
                            }
                        }

                        loginSuccessPacket.AppendBoolean(true); // should client disconnect if sent invalid packets?
                                                                 // (yes!, will get stricter in 1.21.2, apparently)

                        SendPacket(client, loginSuccessPacket);
                        break;
                    }
                    case 0x03 when client.State == ConnectionState.Login: // Login acknowledged
                    {
                        Console.WriteLine("Login acknowledged packet");

                        SendPacket(client,
                            new PacketBuilder(ClientboundPacketId.PluginMessage)
                                .AppendString("minecraft:brand")
                                .AppendBytes("littlecat :3"u8.ToArray())
                        );

                        SendPacket(client,
                            new PacketBuilder(ClientboundPacketId.FeatureFlags)
                                .AppendVarInt(1) // feature count
                                .AppendString("minecraft:vanilla") // dont think this is technically needed
                        );

                        SendPacket(client,
                            new PacketBuilder(ClientboundPacketId.KnownPacks)
                                .AppendVarInt(1) // pack count
                                .AppendString("minecraft") // namespace
                                .AppendString("core") // id 
                                .AppendString("1.21") // version
                        );

                        client.State = ConnectionState.Configuration;
                        SendPacket(client, new PacketBuilder(ClientboundPacketId.FinishConfiguration));
                        break;
                    }
                    case 0x00 when client.State == ConnectionState.Configuration: // Client information
                    {
                        Console.WriteLine("Client information packet");

                        // todo https://wiki.vg/Protocol#Client_Information_.28configuration.29

                        break;
                    }
                    case 0x02 when client.State == ConnectionState.Configuration: // Serverbound plugin message
                    {
                        Console.WriteLine("Serverbound plugin message packet");

                        var channel = stream.ReadString();
                        // plugin messages aren't length prefixed
                        var data = stream.ReadExactly(packetLength - 1 - channel.Length);

                        Console.WriteLine($"Channel: {channel}");
                        Console.WriteLine($"Data: {System.Text.Encoding.Default.GetString(data)}");
                        break;
                    }
                    case 0x03 when client.State == ConnectionState.Configuration: // Acknowledge finish configuration
                    {
                        Console.WriteLine("Acknowledge finish configuration packet");
                        
                        client.State = ConnectionState.Play;
                        break;
                    }
                    case 0x07 when client.State == ConnectionState.Configuration: // Serverbound known packs
                    {
                        Console.WriteLine("Serverbound known packs packet");
                        
                        var packCount = stream.ReadVarInt();
                        for (var i = 0; i < packCount; i++)
                        {
                            var namespaceString = stream.ReadString();
                            var id = stream.ReadString();
                            var version = stream.ReadString();
                            
                            Console.WriteLine($"Namespace: {namespaceString}");
                            Console.WriteLine($"Id: {id}");
                            Console.WriteLine($"Version: {version}");
                            
                            client.KnownPacks.Add(new Pack
                            {
                                Namespace = namespaceString,
                                Id = id,
                                Version = version
                            });
                        }

                        break;
                    }
                    case 0x9999 /* todo */ when client.State == ConnectionState.Configuration: // Finish configuration
                    {
                        Console.WriteLine("Finish configuration packet");
                        client.State = ConnectionState.Play;

                        SendPacket(client,
                            new PacketBuilder(ClientboundPacketId.Play)
                                .AppendInt(0) // player eid
                                .AppendBoolean(false) // is hardcore
                                .AppendVarInt(1) // dimension count
                                .AppendString("minecraft:overworld")
                                .AppendVarInt(0) // max players (ignored)
                                .AppendVarInt(8) // render distance
                                .AppendVarInt(8) // simulation distance
                                .AppendBoolean(false) // hide debug info
                                .AppendBoolean(true) // show respawn screen
                                .AppendBoolean(false) // limited crafting (ignored)
                                .AppendString("") // dimension type
                                .AppendString("minecraft:overworld") // name of joined dimension
                                .AppendLong(00000000) // first 8 bytes of world seed sha-256 hash
                                .AppendByte(0) // game mode
                                .AppendSByte(-1) // previous game mode
                                .AppendBoolean(false) // is debug mode
                                .AppendBoolean(false) // is flat
                                .AppendBoolean(false) // has death location
                                .AppendVarInt(0) // portal cooldown (might be ignored?)
                        );

                        SendPacket(client,
                            new PacketBuilder(ClientboundPacketId.ChunkDataAndUpdateLight)
                                .AppendInt(0) // chunk x
                                .AppendInt(0) // chunk z
                                .AppendNbt(null) // heightmaps // todo
                                .AppendLengthPrefixedByteArray(null) // chunk data
                        );

                        break;
                    }
                    default:
                        throw new InvalidDataException($"Unknown packet 0x{packetId:X} at state {client.State}");
                }

                Console.WriteLine();
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"Exception in client handler: {e}");
        }
        finally
        {
            tcpClient.Close();
            Console.WriteLine($"Disconnected from {tcpClient.Client.RemoteEndPoint}");
        }
    }

    private void SendPacket(Client client, PacketBuilder packet)
    {
        Console.WriteLine($"Sending packet {packet.Id} ({packet.Id:X}) while in {client.State} to {client.Stream.Socket.RemoteEndPoint}");

        var packetBytes = packet.GetBytes();

        if (client.EncryptionActive)
        {
            client.CipherStream!.Write(packetBytes, 0, packetBytes.Length);
        }
        else
        {
            client.Stream.Write(packetBytes, 0, packetBytes.Length);
        }
    }
}