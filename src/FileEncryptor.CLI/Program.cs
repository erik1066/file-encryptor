using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.IO;
using CommandLine;
using FileEncryptor;

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
            FileEncryptor.FileCryptoOperations.EncryptFile(options.Infile
            , options.Outfile
            , options.Password
            , options.InitVector
            , options.Salt
            , options.Iterations);
        }
        else if (options.Decrypt)
        {
            FileEncryptor.FileCryptoOperations.DecryptFile(options.Infile
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
}