using System.Net;
using System.Net.Sockets;
using littlecat.Packets;
using littlecat.Utils;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace littlecat;

public class Server
{
    private const string Version = "1.20.4";
    private const int ProtocolVersion = 765;

    private readonly Config _config;

    private readonly string? _faviconBase64;

    public Server(Config config)
    {
        _config = config;

        if (File.Exists(_config.FaviconPath))
        {
            var faviconBytes = File.ReadAllBytes(_config.FaviconPath);
            _faviconBase64 = Convert.ToBase64String(faviconBytes);
        }
    }

    public async Task StartServer()
    {
        var ipEndPoint = new IPEndPoint(IPAddress.Any, _config.Port);
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

    private void HandleClient(object? state)
    {
        if (state is not TcpClient client) return;

        ThreadLogger.Log($"Connected to {client.Client.RemoteEndPoint}");

        var stream = client.GetStream();
        stream.ReadTimeout = 30_000;

        while (client.Connected)
        {
            Packet packet;
            try
            {
                packet = ReadNextPacket(stream);
            }
            catch (InvalidDataException e)
            {
                // bye bye :3
                ThreadLogger.Warn(e.ToString());
                client.Close();
                return;
            }

            ThreadLogger.Log($"Received packet: {packet.Id:G} ({packet.Id:X})");

            switch (packet)
            {
                case HandshakePacket handshakePacket:
                {
                    ThreadLogger.Log("Handshake packet");

                    ThreadLogger.Log($"Protocol version: {handshakePacket.ProtocolVersion}");
                    ThreadLogger.Log($"Server address: {handshakePacket.ServerAddress}");
                    ThreadLogger.Log($"Server port: {handshakePacket.ServerPort}");
                    ThreadLogger.Log($"Next state: {handshakePacket.NextState:G}");
                    break;
                }
                case StatusRequestPacket:
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
                            ["max"] = _config.MaxPlayers,
                            ["online"] = 0,
                            // ["sample"] = new JArray()
                        },
                        ["description"] = new JObject
                        {
                            ["text"] = _config.Motd
                        },
                        ["favicon"] = _faviconBase64 != null ? "data:image/png;base64," + _faviconBase64 : null,
                        ["enforcesSecureChat"] = false,
                        ["previewsChat"] = false
                    };

                    stream.Write(
                        new PacketBuilder(ClientboundPacketId.StatusResponse)
                            .AppendString(JsonConvert.SerializeObject(response))
                            .GetBytes()
                    );
                    break;
                }
                case PingRequestPacket pingRequestPacket:
                {
                    stream.Write(
                        new PacketBuilder(ClientboundPacketId.PongResponse)
                            .AppendLong(pingRequestPacket.Payload)
                            .GetBytes()
                    );
                    break;
                }
            }
        }
    }

    private Packet ReadNextPacket(Stream stream)
    {
        var packetLength = stream.ReadVarInt();
        ThreadLogger.Log($"Packet length: {packetLength}");

        var packetId = stream.ReadVarInt();

        ThreadLogger.Log($"Received packet id: {packetId:X}");

        switch (packetId)
        {
            case (int)ServerboundPacketId.Handshake:
            {
                if (packetLength == 1) return new StatusRequestPacket();

                var protocolVersion = stream.ReadVarInt();
                var serverAddress = stream.ReadString();
                var serverPort = stream.ReadBigEndianShort();
                var nextState = stream.ReadVarInt();

                return new HandshakePacket(
                    protocolVersion,
                    serverAddress,
                    serverPort,
                    nextState
                );
            }
            case (int)ServerboundPacketId.PingRequest:
            {
                var payload = stream.ReadBigEndianLong();

                return new PingRequestPacket(payload);
            }
            default:
                throw new InvalidDataException($"Unknown packet id: {packetId} (0x{packetId:X})");
        }
    }
}