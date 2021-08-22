using System;
using System.Collections.Generic;
using System.Numerics;
using System.Security.Cryptography;

namespace Crypto
{
    public class Gost
    {
        public static BigInteger bits256 { get; private set; }
        public static BigInteger bits1024 { get; private set; }
        private static BigInteger b { get; set; }
        public static BigInteger a { get; private set; }
        private BigInteger x { get; set; }
        public BigInteger y { get; set; }
        private BigInteger k { get; set; }
        private BigInteger r { get; set; }
        private BigInteger s { get; set; }
        public Gost()
        {
            x = CryptoFunctions.GenerateRandomNumber(16);
            y = CryptoFunctions.MyModPow(a, x, bits1024);
        }
        public static void GenerateParams()
        {
            GeneratePQ();
            GenerateA();
        }
        private static bool GeneratePQ()
        {
            Console.WriteLine("Generating p, q");

            bits256 = CryptoFunctions.GenerateSimpleNumber(16);
            b = CryptoFunctions.GenerateRandomNumber(15);
            bits1024 = BigInteger.Multiply(bits256, b) + 1;
            return CryptoFunctions.MillerRabinTest(bits1024) && bits1024.ToByteArray().Length == 31 ? true : GeneratePQ();
        }
        private static bool GenerateA()
        {
            Console.WriteLine("Generating a");

            BigInteger g = CryptoFunctions.GenerateRandomNumber(16);
            a = CryptoFunctions.MyModPow(g, b, bits1024);
            return BigInteger.Compare(a, 1) == 1 ? true : GenerateA();
        }
        private bool GenerateSigR()
        {
            Console.WriteLine("Generating r");

            k = CryptoFunctions.GenerateRandomNumber(16);
            r = CryptoFunctions.MyModPow(a, k, bits1024) % bits256;
            return r == 0 ? GenerateSigR() : true;
        }
        private bool GenerateSigS(BigInteger hash)
        {
            Console.WriteLine("Generating s\n");

            BigInteger kh = BigInteger.Multiply(k, hash) % bits256;
            BigInteger xr = BigInteger.Multiply(x, r) % bits256;
            s = BigInteger.Add(kh, xr) % bits256;
            return s == 0 ? GenerateSigS(hash) : true;
        }
        public Tuple<byte[], byte[] , byte[]> ComputeSignature(byte[] message)
        {
            Console.WriteLine($"\nq = {bits256} ({bits256.ToByteArray().Length}), p = {bits1024} ({bits1024.ToByteArray().Length})\n");

            MD5 md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(message);

            Console.WriteLine($"Not encrypted hash: {Convert.ToBase64String(hash)}, Length = {hash.Length}\n");

            BigInteger hashNumber = new BigInteger(hash);

            GenerateSigR();
            GenerateSigS(hashNumber);

            byte[] r_bytes = r.ToByteArray();
            byte[] s_bytes = s.ToByteArray();

            Console.WriteLine($"r = {r} ({r_bytes.Length}), s = {s} ({s_bytes.Length})");

            byte[] result = new byte[message.Length + r_bytes.Length + s_bytes.Length];

            message.CopyTo(result, 0);
            r_bytes.CopyTo(result, message.Length);
            s_bytes.CopyTo(result, message.Length + r_bytes.Length);

            Console.WriteLine($"\nEncrypted hash: {Convert.ToBase64String(result)}, Length = {result.Length}\n");

            return Tuple.Create(message, r_bytes, s_bytes);
        }
        public bool CheckSignature(Tuple<byte[], byte[], byte[]> sig)
        {
            byte[] message = sig.Item1;
            BigInteger messageNumber = new BigInteger(message);

            byte[] r_bytes = sig.Item2;
            BigInteger r = new BigInteger(r_bytes);

            byte[] s_bytes = sig.Item3;
            BigInteger s = new BigInteger(s_bytes);
            
            if (BigInteger.Compare(r, bits256) == 1 || BigInteger.Compare(s, bits256) == 1)
                return false;

            MD5 md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(message);
            BigInteger hashNumber = new BigInteger(hash);

            Console.WriteLine($"Recieved hash: {Convert.ToBase64String(hash)}, Length = {hash.Length}\n");

            BigInteger inversedHash = CryptoFunctions.Inverse(hashNumber, bits256);
            BigInteger u1 = BigInteger.Multiply(s, inversedHash) % bits256;
            BigInteger u2 = BigInteger.Multiply(BigInteger.Negate(r), inversedHash) % bits256; // < 0 ?
            while(u2.Sign == -1)
            {
                //Console.WriteLine(u2);
                u2 = BigInteger.Add(u2, bits256);
            }
            BigInteger v = (BigInteger.Multiply(CryptoFunctions.MyModPow(a, u1, bits1024), CryptoFunctions.MyModPow(y, u2, bits1024)) % bits1024) % bits256;

            Console.WriteLine($"v = {v} ({v.ToByteArray().Length}), r = {r} ({r_bytes.Length})");

            if (BigInteger.Compare(v, r) == 0)
                return true;
            else
                return false;
        }
    }
}
