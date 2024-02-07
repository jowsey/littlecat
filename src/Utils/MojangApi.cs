using Newtonsoft.Json.Linq;

namespace littlecat.Utils;

public static class MojangApi
{
    private static HttpClient _client = new();
    
    public static async Task<JObject> GetUserInfo(string username, string hash)
    {
        ThreadLogger.Log($"Getting user info for {username} with hash {hash}");
        var url = $"https://sessionserver.mojang.com/session/minecraft/hasJoined?username={username}&serverId={hash}";
        
        var response = await _client.GetAsync(url);
        var responseString = await response.Content.ReadAsStringAsync();
        
        ThreadLogger.Log($"Got response: {responseString}");

        return JObject.Parse(responseString);
    }
}