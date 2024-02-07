using System.Globalization;
using System.Net;
using System.Net.Sockets;
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

public enum ConnectionState
{
    Handshake,
    Configuration,
    Play
}

public enum HandshakeNextState
{
    Status = 1,
    Login = 2
}

public class ClientState
{
    public required NetworkStream Stream;
    public CipherStream? CipherStream;

    // State
    public ConnectionState ConnectionState = ConnectionState.Handshake;
    public HandshakeNextState HandshakeNextState;
    public bool WaitingForEncryptionResponse;

    // Encryption
    public readonly byte[] VerifyToken = new byte[4];
    public bool EncryptionActive;

    // User
    public string? Username;
}

public class Server
{
    private const string Version = "1.20.4";
    private const int ProtocolVersion = 765;

    private readonly Config _configHandler;

    private readonly string? _faviconBase64;

    private readonly byte[] _publicKeyDer;

    private readonly IBufferedCipher _rsaDecrypt;

    private PaddedBufferedBlockCipher? _aesEncrypt;
    private PaddedBufferedBlockCipher? _aesDecrypt;

    public Server(Config configHandler)
    {
        _configHandler = configHandler;

        if (File.Exists(_configHandler.FaviconPath))
        {
            var faviconBytes = File.ReadAllBytes(_configHandler.FaviconPath);
            _faviconBase64 = Convert.ToBase64String(faviconBytes);
        }

        // god save me
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
                ThreadLogger.Log("Waiting for a connection...");

                var client = await listener.AcceptTcpClientAsync();

                ThreadPool.QueueUserWorkItem(HandleClient, client);
            }
        }
        catch (SocketException e)
        {
            ThreadLogger.Log($"SocketException: {e}");
        }
        finally
        {
            listener.Stop();
        }
    }

    private async void HandleClient(object? state)
    {
        if (state is not TcpClient client) return;

        ThreadLogger.Log($"Connected to {client.Client.RemoteEndPoint}");

        var clientState = new ClientState
        {
            Stream = client.GetStream()
        };

        while (client.Connected)
        {
            Stream stream = clientState.EncryptionActive
                ? clientState.CipherStream!
                : clientState.Stream;

            var packetLength = stream.ReadVarInt();
            var packetId = stream.ReadVarInt();

            ThreadLogger.Log($"Received packet with id {packetId:X} and length {packetLength}");

            if (clientState.ConnectionState == ConnectionState.Handshake)
            {
                switch (packetId)
                {
                    case 0x00:
                    {
                        // Status request
                        if (clientState.HandshakeNextState == HandshakeNextState.Status)
                        {
                            ThreadLogger.Log("Status request packet");

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
                                ["favicon"] = _faviconBase64 != null ? "data:image/png;base64," + _faviconBase64 : null,
                                ["enforcesSecureChat"] = false,
                                ["previewsChat"] = false
                            };

                            SendPacket(clientState,
                                new PacketBuilder(ClientboundPacketId.StatusResponse)
                                    .AppendString(JsonConvert.SerializeObject(response))
                            );
                            break;
                        }

                        // Login start
                        if (clientState.HandshakeNextState == HandshakeNextState.Login)
                        {
                            ThreadLogger.Log("Login start packet");

                            var playerName = stream.ReadString();
                            var playerUuid = stream.ReadUuid();

                            ThreadLogger.Log($"Player name: {playerName}");
                            ThreadLogger.Log($"Player UUID: {playerUuid}");

                            clientState.Username = playerName;

                            new Random().NextBytes(clientState.VerifyToken);

                            SendPacket(clientState,
                                new PacketBuilder(ClientboundPacketId.EncryptionRequest)
                                    .AppendString("") // server id
                                    .AppendLengthPrefixedBytes(_publicKeyDer)
                                    .AppendLengthPrefixedBytes(clientState.VerifyToken)
                            );

                            clientState.WaitingForEncryptionResponse = true;
                            break;
                        }

                        _ = stream.ReadVarInt(); // protocol version
                        _ = stream.ReadString(); // server address
                        _ = stream.ReadShort(); // server port
                        var nextState = (HandshakeNextState)stream.ReadVarInt();

                        clientState.HandshakeNextState = nextState;

                        ThreadLogger.Log("Handshake packet");
                        break;
                    }
                    case 0x01:
                    {
                        // Encryption response
                        if (clientState.WaitingForEncryptionResponse)
                        {
                            ThreadLogger.Log("Encryption response packet");

                            var sharedSecret = stream.ReadLengthPrefixedBytes();
                            var verifyToken = stream.ReadLengthPrefixedBytes();

                            var decryptedVerifyToken = _rsaDecrypt.DoFinal(verifyToken);
                            var decryptedSharedSecret = _rsaDecrypt.DoFinal(sharedSecret);

                            if (!clientState.VerifyToken.SequenceEqual(decryptedVerifyToken))
                            {
                                ThreadLogger.Log("Verify tokens do not match");
                                client.Close();
                                break;
                            }

                            ThreadLogger.Log("Verify tokens match");

                            var key = new KeyParameter(decryptedSharedSecret);
                            var iv = new ParametersWithIV(key, decryptedSharedSecret);

                            _aesEncrypt = new PaddedBufferedBlockCipher(new CfbBlockCipher(new AesEngine(), 8));
                            _aesEncrypt.Init(true, iv);

                            _aesDecrypt = new PaddedBufferedBlockCipher(new CfbBlockCipher(new AesEngine(), 8));
                            _aesDecrypt.Init(false, iv);

                            clientState.CipherStream =
                                new CipherStream(clientState.Stream, _aesDecrypt, _aesEncrypt);
                            clientState.EncryptionActive = true;

                            var digest = decryptedSharedSecret.Concat(_publicKeyDer).ToMinecraftShaHexDigest();

                            var hasJoinedInfo = await MojangApi.GetUserInfo(clientState.Username!, digest);
                            var uuid = hasJoinedInfo["id"]?.ToObject<string>();

                            var packetBuilder = new PacketBuilder(ClientboundPacketId.LoginSuccess)
                                .AppendUuid(UInt128.Parse(uuid!, NumberStyles.HexNumber))
                                .AppendString(clientState.Username!);

                            var numberOfProperties = hasJoinedInfo["properties"]?.Count() ?? 0;

                            packetBuilder.AppendVarInt(numberOfProperties);

                            if (numberOfProperties > 0)
                            {
                                foreach (var property in hasJoinedInfo["properties"]!)
                                {
                                    packetBuilder
                                        .AppendString(property["name"]!.ToObject<string>()!)
                                        .AppendString(property["value"]!.ToObject<string>()!);

                                    if (property["signature"] != null)
                                    {
                                        packetBuilder
                                            .AppendBoolean(true)
                                            .AppendString(property["signature"]!.ToObject<string>()!);
                                    }
                                }
                            }

                            SendPacket(clientState, packetBuilder);

                            clientState.WaitingForEncryptionResponse = false;
                            break;
                        }

                        // Ping request
                        ThreadLogger.Log("Ping request packet");
                        var payload = stream.ReadLong();

                        SendPacket(clientState,
                            new PacketBuilder(ClientboundPacketId.PongResponse)
                                .AppendLong(payload)
                        );

                        client.Close();
                        break;
                    }
                    case 0x03:
                    {
                        ThreadLogger.Log("Login acknowledged packet");
                        clientState.ConnectionState = ConnectionState.Configuration;
                        break;
                    }
                    default:
                    {
                        throw new InvalidDataException($"Unknown packet id: {packetId} (0x{packetId:X})");
                    }
                }
            }

            Console.WriteLine();
        }
    }

    private void SendPacket(ClientState clientState, PacketBuilder packet)
    {
        var packetBytes = packet.GetBytes();

        if (clientState.EncryptionActive)
        {
            clientState.CipherStream!.Write(packetBytes, 0, packetBytes.Length);
            return;
        }

        clientState.Stream.Write(packetBytes, 0, packetBytes.Length);
    }
}