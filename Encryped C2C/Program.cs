using System;
using System.Net;

class Program {
    static void Main(string[] args) {
        IPAddress host = IPAddress.Any;
        bool RunServer = false;

        // safeguard arguments
        if (args.Length == 0) {
            throw new ArgumentException("Usage: application [<host-to-bind>] <port-to-bind>");
        }

        // if argument length is 1, consider it as port and run server
        // otherwise treat as client and connect to host (arg1) with port (arg2)
        int port;
        if (args.Length == 1) {
            RunServer = true;
            port = Convert.ToInt32(args[0]);
        } else {
            host = IPAddress.Parse(args[0]);
            port = Convert.ToInt32(args[1]);
        }

        // spawn the worker based on arguments
        if (RunServer) {
            using var server = new Server(port); server.Setup();
        } else {
            using var client = new Client(host, port); client.Setup();
        }
    }
}
