using System;
using System.Linq;
using System.Diagnostics;
using PeNet;

static class Utils {

    /// <summary>
    /// Convert hex bytes to string
    /// </summary>
    /// <param name="b"></param>
    /// <returns></returns>
    public static string Hexify(byte[] b) {
        string[] hex = BitConverter.ToString(b).Split("-").Reverse().ToArray();
        return "0x" + string.Join("", hex); 
    }
}

class Program {
    
    static void Main(string[] args) {
        // safeguard arguments
        if (args.Length == 0) {
            Console.Error.WriteLine("Usage: '{0}' <PE FILE>", Process.GetCurrentProcess().MainModule.ModuleName);
            Environment.Exit(1);
        }

        // check if it is a PE file
        if (!PeFile.IsPeFile(args[0])) {
            Console.Error.WriteLine("[x] '{0}' is not a valid PE file.", args[0]);
            Environment.Exit(1);
        }

        var pe = new PeFile(args[0]);

        // ==================================
        // Image NT Headers (PE File Only)
        // ==================================
        Console.WriteLine("[!] PE File Header");
        var fh = pe.ImageNtHeaders.FileHeader;
        Console.WriteLine("\t[+] Machine Type: {0}", fh.Machine);
        Console.WriteLine("\t[+] Number of Sections: {0}", fh.NumberOfSections);
        Console.WriteLine("\t[+] Date and time of image creation: {0}", new DateTime(1970, 01, 01, 0, 0, 0).AddSeconds(fh.TimeDateStamp).ToString());
        Console.WriteLine("\t[+] Number of Symbols: {0}", fh.NumberOfSymbols);
        Console.WriteLine("\t[+] File Characteristrics: {0}", fh.Characteristics);

        Console.WriteLine("[!] Optional Header");
        var oh = pe.ImageNtHeaders.OptionalHeader;
        Console.WriteLine("\t[+] Magic: {0}", oh.Magic);
        Console.WriteLine("\t[+] Linker Version: {0}.{1}", oh.MajorLinkerVersion, oh.MinorLinkerVersion);
        Console.WriteLine("\t[+] Size of Code: {0}", oh.SizeOfCode);
        Console.WriteLine("\t[+] Size of Initialized Data: {0}", oh.SizeOfInitializedData);
        Console.WriteLine("\t[+] Size of Uninitialized Data: {0}", oh.SizeOfUninitializedData);
        Console.WriteLine("\t[+] Address of Entrypoint: {0}", Utils.Hexify(BitConverter.GetBytes(oh.AddressOfEntryPoint)));
        Console.WriteLine("\t[+] Base of Code (RVA): {0}", Utils.Hexify(BitConverter.GetBytes(oh.BaseOfCode)));
        Console.WriteLine("\t[+] Base of Code (VA): {0}", Utils.Hexify(BitConverter.GetBytes(oh.BaseOfCode + oh.ImageBase)));
        Console.WriteLine("\t[+] Base of Image Loading (VA): {0}", Utils.Hexify(BitConverter.GetBytes(oh.ImageBase)));
        Console.WriteLine("\t[+] Section Alignment: {0}", oh.SectionAlignment);
        Console.WriteLine("\t[+] File Alignment: {0}", oh.FileAlignment);
        Console.WriteLine("\t[+] Operating System Version Required: {0}.{1}", oh.MajorOperatingSystemVersion, oh.MinorOperatingSystemVersion);
        Console.WriteLine("\t[+] Image Version Required: {0}.{1}", oh.MajorImageVersion, oh.MinorImageVersion);
        Console.WriteLine("\t[+] Subsystem Version to Execute File: {0}.{1}", oh.MajorSubsystemVersion, oh.MinorSubsystemVersion);
        Console.WriteLine("\t[+] Size of Image File: {0}", oh.SizeOfImage);
        Console.WriteLine("\t[+] Size of all Headers: {0}", oh.SizeOfHeaders);
        Console.WriteLine("\t[+] Subsystem Required to Execute: {0}", oh.Subsystem);
        Console.WriteLine("\t[+] Dll Characteristics of Image: {0}", oh.DllCharacteristics);
        Console.WriteLine("\t[+] Size of Stack Commit and Reserve: {0}\t{1}", oh.SizeOfStackCommit, oh.SizeOfStackReserve);
        Console.WriteLine("\t[+] Size of Heap Commit and Reserve: {0}\t{1}", oh.SizeOfHeapCommit, oh.SizeOfHeapReserve);
        Console.WriteLine("\t[+] Number of Directory Entries: {0}", oh.NumberOfRvaAndSizes);

        // ==================================
        // Available Data Directories
        // (If it is not present, the contents and title will be skipped)
        // ==================================
        if (pe.ExportedFunctions !=null && pe.ExportedFunctions.Length > 0)
        {
            Console.WriteLine("[!] Exported Functions");
            foreach (var f in pe.ExportedFunctions)
            {
                Console.WriteLine("\t[+] Function Name: {0}", f.Name);
                Console.WriteLine("\t    Ordinal Number: {0}", f.Ordinal);
                Console.WriteLine("\t    Address: {0}", f.Address.ToHexString());
            }
        }

        if (pe.ImportedFunctions != null && pe.ImportedFunctions.Length > 0)
        {
            Console.WriteLine("[!] Imported Functions");
            foreach (var f in pe.ImportedFunctions)
            {
                Console.WriteLine("\t[+] Function Name: {0}", f.Name);
                Console.WriteLine("\t    DLL: {0}", f.DLL);
                Console.WriteLine("\t    IAT Offset: {0}", f.IATOffset);
            }
        }

        if (pe.ImageResourceDirectory != null)
        {
            Console.WriteLine("[!] Resource Directories");
            Console.WriteLine("\t[+] Characteristics: {0}", pe.ImageResourceDirectory.Characteristics.ToHexString());
            Console.WriteLine("\t[+] Version: {0}.{1}", pe.ImageResourceDirectory.MajorVersion, pe.ImageResourceDirectory.MinorVersion);
            Console.WriteLine("\t[+] Total Entries: {0}", pe.ImageResourceDirectory.NumberOfIdEntries + pe.ImageResourceDirectory.NumberOfNameEntries);
            Console.WriteLine("\t[!] Data Entries");

            foreach (var e in pe.ImageResourceDirectory.DirectoryEntries)
            {
                Console.WriteLine("\t\t[+] ID: {0}\t\tName: {1}", e.ID, e.NameResolved);
                Console.WriteLine("\t\t    Entry Type: {0}", e.IsIdEntry ? "ID Entry" : e.IsNamedEntry ? "Named Entry" : "Unknown");
                Console.WriteLine("\t\t    Data is Directory: {0}", e.DataIsDirectory);
            }
        }

        if(pe.ExceptionDirectory.Length > 0)
        {
            Console.WriteLine("[!] Exception Directory");
            foreach (var e in pe.ExceptionDirectory)
            {
                Console.WriteLine("\t[+] Function Start: {0}\t\tFunction End: {1}", e.FunctionStart.ToHexString(), e.FunctionEnd.ToHexString());
                Console.WriteLine("\t    Unwind Information");
                Console.WriteLine("\t    \tVersion: {0}\t\tFlags: {1}", e.ResolvedUnwindInfo.Version, e.ResolvedUnwindInfo.Flags);
                Console.WriteLine("\t    \tFunction Entry: {0}", e.ResolvedUnwindInfo.FunctionEntry.ToHexString());
                Console.WriteLine("\t    \tCount of Codes: {0}", e.ResolvedUnwindInfo.CountOfCodes);
                Console.WriteLine("\t    \tUnwind Codes: {0} entries", e.ResolvedUnwindInfo.UnwindCode.Length);
                foreach (var c in e.ResolvedUnwindInfo.UnwindCode)
                {
                    Console.WriteLine("\t    \t    \tUnwind Operation: {0}", c.UnwindOp);
                    Console.WriteLine("\t    \t    \tFrame Offset: {0}\t\tCode Offset: {1}", c.FrameOffset.ToHexString(), c.CodeOffset.ToHexString());
                }
            }
        }

        if(pe.ImageRelocationDirectory.Length > 0)
        {
            Console.WriteLine("[!] Relocation Directory");
            foreach (var e in pe.ImageRelocationDirectory)
            {
                Console.WriteLine("\t[+] Size of Block: {0}\t\tVirtual Address: {1}", e.SizeOfBlock.ToHexString(), e.VirtualAddress.ToHexString());
                Console.WriteLine("\t    Type Offsets: {0} entries", e.TypeOffsets.Length);
                foreach (var t in e.TypeOffsets)
                {
                    Console.WriteLine("\t    \tOffset: {0}\t\tType: {1}", t.Offset.ToHexString(), t.Type);
                }
            }
        }

        if(pe.ImageDebugDirectory.Length > 0)
        {
            Console.WriteLine("[!] Debug Directory");
            foreach (var e in pe.ImageDebugDirectory)
            {
                Console.WriteLine("\t[+] Size of Data: {0}\t\tPointer to Raw Data: {1}", e.SizeOfData.ToHexString(), e.PointerToRawData.ToHexString());
                Console.WriteLine("\t    Version: {0}.{1}\t\t\t\tType: {2}", e.MajorVersion, e.MinorVersion, e.Type);
                Console.WriteLine("\t    Characteristics: {0}\t\tAddress of Raw Data: {1}", e.Characteristics.ToHexString(), e.AddressOfRawData.ToHexString());
            }
        }

        if (pe.ImageTlsDirectory != null)
        {
            Console.WriteLine("[!] TLS Directory");
            Console.WriteLine("\t[+] Characteristics: {0}", pe.ImageTlsDirectory.Characteristics);
            Console.WriteLine("\t[+] Address of Callbacks: {0}", pe.ImageTlsDirectory.AddressOfCallBacks.ToHexString());
            Console.WriteLine("\t[+] Address of Index: {0}", pe.ImageTlsDirectory.AddressOfIndex.ToHexString());
            Console.WriteLine("\t[+] Start of Raw Data: {0}\t\tEnd of Raw Data: {1}", pe.ImageTlsDirectory.StartAddressOfRawData.ToHexString(), pe.ImageTlsDirectory.EndAddressOfRawData);
            Console.WriteLine("\t[+] Size of ZeroFile: {0}", pe.ImageTlsDirectory.SizeOfZeroFill);
            if (pe.ImageTlsDirectory.TlsCallbacks.Length > 0)
            {
                Console.WriteLine("\t[+] TLS Callbacks: {0} entries", pe.ImageTlsDirectory.TlsCallbacks.Length);
                foreach (var c in pe.ImageTlsDirectory.TlsCallbacks)
                {
                    Console.WriteLine("\t\t{0}", c.Callback.ToHexString());
                }
            }
        }

        if(pe.ImageLoadConfigDirectory != null)
        {
            Console.WriteLine("[!] Load Config Directory");
            Console.WriteLine("\t[+] Size: {0}\t\tEdit List: {1}", pe.ImageLoadConfigDirectory.Size, pe.ImageLoadConfigDirectory.EditList);
            Console.WriteLine("\t[+] Critial Section Default Timeout: {0}", pe.ImageLoadConfigDirectory.CriticalSectionDefaultTimeout);
            Console.WriteLine("\t[+] Commit Free Block Threshold: {0}\t\tCommit Total Free Threshold: {1}", pe.ImageLoadConfigDirectory.DeCommitFreeBlockThreshold, pe.ImageLoadConfigDirectory.DeCommitTotalFreeThreshold);
            Console.WriteLine("\t[+] Version: {0}.{1}", pe.ImageLoadConfigDirectory.MajorVesion, pe.ImageLoadConfigDirectory.MinorVersion);
        }

        if(pe.ImageBoundImportDescriptor != null)
        {
            Console.WriteLine("[!] Bound Import Directory");
            Console.WriteLine("\t[+] Number of Module Forwarder Refs: {0}", pe.ImageBoundImportDescriptor.NumberOfModuleForwarderRefs);
            Console.WriteLine("\t[+] Offset Module Name: {0}", pe.ImageBoundImportDescriptor.OffsetModuleName);
        }


        // ==================================
        // Image Section Headers
        // ==================================
        if (pe.ImageSectionHeaders != null && pe.ImageSectionHeaders.Length > 0)
        {
            Console.WriteLine("[!] Sections");
            foreach (var s in pe.ImageSectionHeaders)
            {
                Console.WriteLine("\t[!] Name: {0}", s.Name);
                Console.WriteLine("\t    Virtual Size: {0}", s.VirtualSize.ToHexString());
                Console.WriteLine("\t    Characteristics: {0}", s.Characteristics);
            }
        }
    }
}
