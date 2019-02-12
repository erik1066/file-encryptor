using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.IO;
using CommandLine;

class Program
{
    public class Options
    {
        public bool Decrypt => Mode.Equals("d", StringComparison.OrdinalIgnoreCase);

        public bool Encrypt => Mode.Equals("e", StringComparison.OrdinalIgnoreCase);

        [Option("mode", Required = true, HelpText = "Sets mode, use 'e' for encrypt and 'd' for decrypt.")]
        public string Mode { get; set; }

        [Option("infile", Required = true, HelpText = "Input file.")]
        public string Infile { get; set; }

        [Option("outfile", Required = true, HelpText = "Output file.")]
        public string Outfile { get; set; }

        [Option("pwd", Required = true, HelpText = "Password.")]
        public string Password { get; set; }

        [Option("init", Required = true, HelpText = "Initialization vector.")]
        public string InitVector { get; set; }

        [Option("salt", Required = true, HelpText = "Salt value.")]
        public string Salt { get; set; }

        [Option("iter", Required = true, HelpText = "Number of iterations.")]
        public int Iterations { get; set; }
    }

    static int RunOptionsAndReturnExitCode(Options options)
    {
        if (options.Decrypt && options.Encrypt)
        {
            Console.WriteLine("Cannot both encrypt and decrypt at the same time.");
            return 1;
        }
        else if (!options.Decrypt && !options.Encrypt)
        {
            Console.WriteLine("Must select either encryption or decryption mode.");
            return 1;
        }
        else if (options.Infile.Equals(options.Outfile, StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("Infile and outfile must be different.");
            return 1;
        }

        if (options.Encrypt)
        {
            Program.EncryptFile(options.Infile
            , options.Outfile
            , options.Password
            , options.InitVector
            , options.Salt
            , options.Iterations);
        }
        else if (options.Decrypt)
        {
            Program.DecryptFile(options.Infile
            , options.Outfile
            , options.Password
            , options.InitVector
            , options.Salt
            , options.Iterations);
        }

        return 0;
    }

    static int HandleParseError(IEnumerable<Error> errs)
    {
        foreach (var error in errs)
        {
            Console.WriteLine(error);
        }
        return 1;
    }

    static int Main(string[] args)
    {
        CommandLine.Parser.Default.ParseArguments<Options>(args)
            .WithParsed<Options>(opts => RunOptionsAndReturnExitCode(opts))
            .WithNotParsed<Options>((errs) => HandleParseError(errs));

        return 0;
    }

    public static void EncryptFile(string inputFileName, string outputFileName, string password, string initVector, string saltValue, int iterations)
    {
        using (FileStream fsInput = new FileStream(inputFileName,
            FileMode.Open,
            FileAccess.Read))
        {

            using (FileStream fsEncrypted = new FileStream(outputFileName,
                            FileMode.Create,
                            FileAccess.Write))
            {

                byte[] salt = Encoding.ASCII.GetBytes(saltValue);
                Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, iterations);
                RijndaelManaged SymmetricKey = new RijndaelManaged();
                SymmetricKey.Padding = PaddingMode.PKCS7;
                SymmetricKey.KeySize = 256;
                SymmetricKey.Mode = CipherMode.CBC;
                SymmetricKey.Key = key.GetBytes(SymmetricKey.KeySize / 8);

                GCHandle gch = GCHandle.Alloc(SymmetricKey.Key, GCHandleType.Pinned);

                SymmetricKey.IV = ASCIIEncoding.ASCII.GetBytes(initVector);
                SymmetricKey.BlockSize = 128;

                initVector = string.Empty;
                saltValue = string.Empty;

                ICryptoTransform aesEncrypt = SymmetricKey.CreateEncryptor(SymmetricKey.Key, SymmetricKey.IV);
                using (CryptoStream cryptostream = new CryptoStream(fsEncrypted,
                                    aesEncrypt,
                                    CryptoStreamMode.Write))
                {
                    byte[] bytearrayinput = new byte[fsInput.Length - 1];
                    fsInput.Read(bytearrayinput, 0, bytearrayinput.Length);
                    cryptostream.Write(bytearrayinput, 0, bytearrayinput.Length);
                }

#if WIN64
                ZeroMemory(gch.AddrOfPinnedObject(), 32);
#endif
                gch.Free();

                SymmetricKey.Clear();
            }
        }
    }

    public static void DecryptFile(string inputFileName, string outputFileName, string password, string initVector, string saltValue, int iterations)
    {
        byte[] salt = Encoding.ASCII.GetBytes(saltValue);
        Rfc2898DeriveBytes key = new Rfc2898DeriveBytes(password, salt, iterations);
        RijndaelManaged SymmetricKey = new RijndaelManaged();
        SymmetricKey.Padding = PaddingMode.PKCS7;
        SymmetricKey.KeySize = 256;
        SymmetricKey.Mode = CipherMode.CBC;
        SymmetricKey.Key = key.GetBytes(SymmetricKey.KeySize / 8);

        GCHandle gch = GCHandle.Alloc(SymmetricKey.Key, GCHandleType.Pinned);

        SymmetricKey.IV = ASCIIEncoding.ASCII.GetBytes(initVector);
        SymmetricKey.BlockSize = 128;

        initVector = string.Empty;
        saltValue = string.Empty;

        FileStream fsread = new FileStream(inputFileName,
                                FileMode.Open,
                                FileAccess.Read);

        ICryptoTransform aesDecrypt = SymmetricKey.CreateDecryptor(SymmetricKey.Key, SymmetricKey.IV);

        CryptoStream cryptostreamDecr = new CryptoStream(fsread,
                                                        aesDecrypt,
                                                        CryptoStreamMode.Read);
        if (File.Exists(outputFileName))
        {
            File.Delete(outputFileName);
        }

        FileStream fsOut = new FileStream(outputFileName, FileMode.Create);

        try
        {
            int data;
            while ((data = cryptostreamDecr.ReadByte()) != -1)
                fsOut.WriteByte((byte)data);

            cryptostreamDecr.Flush();
            cryptostreamDecr.Close();
            cryptostreamDecr.Dispose();
        }
        catch (CryptographicException ex)
        {
            throw new CryptographicException("There was a problem decrypting the file. Check the password and try again.", ex);
        }
        finally
        {
            if (fsOut != null)
            {
                fsOut.Close();
            }

            fsread.Close();

#if WIN64
            ZeroMemory(gch.AddrOfPinnedObject(), 32);
#endif
            gch.Free();

            SymmetricKey.Clear();
        }
    }

    [System.Runtime.InteropServices.DllImport("KERNEL32.DLL", EntryPoint = "RtlZeroMemory")]
    public static extern bool ZeroMemory(IntPtr Destination, int Length);    
}

