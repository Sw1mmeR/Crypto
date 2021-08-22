using System;
using System.Collections.Generic;
using System.IO;
using System.Numerics;
using System.Text;
using System.Windows.Forms;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Security.Cryptography;

namespace Crypto
{
    public class Rsa
    {
        static Stopwatch stopWatch;
        static TimeSpan ts;
        public static int _user_id = 0;
        public int _numberOfBytes;
        public BigInteger EulersFunction { get; set; }
        public BigInteger OpenExp { get; private set; }
        public Tuple<BigInteger, BigInteger> PublicKey { get; private set; }
        public Tuple<BigInteger, BigInteger> PrivateKey { get; set; }
        public Tuple<BigInteger, BigInteger> RecievedPublicKey { get; set; }
        public Rsa(int numberOfBytes = 16)
        {
            stopWatch = new Stopwatch();
            _numberOfBytes = numberOfBytes;

            GeneratePublicKey();
            GeneratePrivateKey();
            RecievedPublicKey = PublicKey;
            //WriteKeys();
            ++_user_id;
        }
        private void GeneratePublicKey()
        {
            BigInteger p = CryptoFunctions.GenerateSimpleNumber(_numberOfBytes);
            BigInteger q = CryptoFunctions.GenerateSimpleNumber(_numberOfBytes);
            BigInteger n = BigInteger.Multiply(p, q);

            EulersFunction = BigInteger.Multiply(BigInteger.Add(p, -1), BigInteger.Add(q, -1));

            GenerateOpenExp();

            PublicKey = Tuple.Create(OpenExp, n);
        }
        private void GeneratePrivateKey()
        {
            var tuple = CryptoFunctions.ExtendedEuclideanAlgorithm(EulersFunction, OpenExp);
            BigInteger D = tuple.Item3 > 0 ? tuple.Item3 : tuple.Item2;
            var privateKey = Tuple.Create(D, PublicKey.Item2);
            PrivateKey = privateKey;
            if (BigInteger.Multiply(D, OpenExp) % EulersFunction != 1)
            {
                GeneratePublicKey();
                GeneratePrivateKey();
            }
        }
        public static void Swap(Rsa a, Rsa b)
        {
            a.RecievedPublicKey = b.PublicKey;
            b.RecievedPublicKey = a.PublicKey;
        }
        public byte[] Decode(byte[] message) // sheck! метод считать строку
        {
            BigInteger res = new BigInteger(message);
            BigInteger decoded = CryptoFunctions.MyModPow(res, PrivateKey.Item1, PrivateKey.Item2);
            byte[] byteDecoded = decoded.ToByteArray();          
            return byteDecoded;
        }

        public byte[] Encode(byte[] bytes)
        {
            BigInteger mess = new BigInteger(bytes);
            BigInteger resNumber = CryptoFunctions.MyModPow(mess, RecievedPublicKey.Item1, RecievedPublicKey.Item2);

            return resNumber.ToByteArray();
        }
        public List<byte[]> EncodeList(List<byte[]> list)
        {
            List<byte[]> result = new List<byte[]>();            
            foreach(var bytes in list)
            {
                result.Add(Encode(bytes));
            }
            return result;
        }
        public List<byte[]> DecodeList(List<byte[]> list)
        {
            List<byte[]> result = new List<byte[]>();
            foreach (var bytes in list)
            {
                var decoded = Decode(bytes);
                result.Add(decoded);
                //DecodedMessage += decoded + " ";
            }
            return result;
        }
        public Tuple<List<byte[]>, string> EncodeListForms(List<byte[]> list, ProgressBar bar = null)
        {
            stopWatch.Start();

            bar.Value = 0; bar.Maximum = list.Count - (int)0.1 * list.Count;
            List<byte[]> result = new List<byte[]>();
            foreach (var bytes in list)
            {
                result.Add(Encode(bytes));
                bar.Value++;
            }

            stopWatch.Stop();
            ts = stopWatch.Elapsed;
            stopWatch.Reset();


            string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                ts.Hours, ts.Minutes, ts.Seconds,
                ts.Milliseconds / 10);

            return Tuple.Create(result, "RunTime: " + elapsedTime);
        }
        public Tuple<List<byte[]>, string> DecodeListBigfile(List<byte[]> list, double percent = 0.3, ProgressBar bar = null)
        {
            stopWatch.Start();

            bar.Value = 0; bar.Maximum = list.Count - (int)0.1 * list.Count;
            List<byte[]> result = new List<byte[]>();
            for (int i = 0; i < list.Count; ++i)
            {
                if(i < (int)percent * list.Count)
                {
                    var decoded = Decode(list[i]);
                    result.Add(decoded);
                }
                else
                {
                    result.Add(list[i]);
                }
                bar.Value++;
                //DecodedMessage += decoded + " ";
            }

            stopWatch.Stop();

            ts = stopWatch.Elapsed;
            stopWatch.Reset();

            string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                ts.Hours, ts.Minutes, ts.Seconds,
                ts.Milliseconds / 10);
            return Tuple.Create(result, "RunTime: " + elapsedTime);

        }
        public Tuple<List<byte[]>, string> DecodeListForms(List<byte[]> list, ProgressBar bar = null)
        {
            stopWatch.Start();

            bar.Value = 0; bar.Maximum = list.Count - (int)0.1 * list.Count;
            List<byte[]> result = new List<byte[]>();
            foreach (var bytes in list)
            {
                var decoded = Decode(bytes);
                result.Add(decoded);
                bar.Value++;
            }

            stopWatch.Stop();

            ts = stopWatch.Elapsed;
            stopWatch.Reset();

            string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
                ts.Hours, ts.Minutes, ts.Seconds,
                ts.Milliseconds / 10);
            
            return Tuple.Create(result, "RunTime: " + elapsedTime);
        }
        public void WriteKeys(string path)
        {
            using(StreamWriter writer = new StreamWriter(path + _user_id + "PublicKey.txt"))
            {
                writer.Write(PublicKey.Item1 + ":" + PublicKey.Item2);
            }
            using (StreamWriter writer = new StreamWriter(path + _user_id + "PrivateKey.txt"))
            {
                writer.Write(PrivateKey.Item1 + ":" + PrivateKey.Item2);
            }
        }
        public byte[] ComputeSignatyre(byte[] message)
        {
            var md5 = new SHA256Managed();
            //var md5 = MD5.Create();
            byte[] hash = md5.ComputeHash(message);
            byte[] s = CryptoFunctions.MyModPow(new BigInteger(hash), PrivateKey.Item1, PrivateKey.Item2).ToByteArray();

            Console.WriteLine($"Not encrypted hash: {new BigInteger(hash)}\n");
            Console.WriteLine($"Encrypted hash: {new BigInteger(s)}\n");

            byte[] sig = new byte[message.Length + s.Length];

            message.CopyTo(sig, 0);
            s.CopyTo(sig, message.Length);

            return sig;
        }
        public bool CheckSignature(byte[] sig, string writing_path = "")
        {
            byte[] message = new byte[sig.Length - _numberOfBytes * 2];
            byte[] hashPart = new byte[_numberOfBytes * 2];

            Array.Copy(sig, 0, message, 0, message.Length);
            Array.Copy(sig, message.Length, hashPart, 0, hashPart.Length);

            if(writing_path != "")
                File.WriteAllBytes(writing_path, message);

            var md5 = new SHA256Managed();
            byte[] hash = md5.ComputeHash(message);
            
            var decoed = CryptoFunctions.MyModPow(new BigInteger(hashPart), PublicKey.Item1, PublicKey.Item2);

            Console.WriteLine($"Decrypted hash: {decoed}\n");

            if (new BigInteger(hash) == decoed)
                return true;
            else
                return false;
        }
        public void SetPublicKey(BigInteger e, BigInteger p) =>
            PublicKey = Tuple.Create(e, p);
        public void SetPublicKey(Tuple<BigInteger, BigInteger> tuple) =>
            PublicKey = tuple;
        public void SetPrivateKey(BigInteger d, BigInteger p) =>
            PrivateKey = Tuple.Create(d, p);
        public void SetPrivateKey(Tuple<BigInteger, BigInteger> tuple) =>
            PrivateKey = tuple;
        public Tuple<BigInteger, BigInteger> GetPrivateKey() =>
            PrivateKey;
        private BigInteger GenerateOpenExp()
        {
            OpenExp = CryptoFunctions.GenerateRandomNumber(_numberOfBytes);
            return OpenExp < EulersFunction && CryptoFunctions.EuclideanAlgorithm(OpenExp, EulersFunction) ? OpenExp : GenerateOpenExp();
        }
        public void ShowPublicKey() =>
            Console.WriteLine($"Public key: ({PublicKey.Item1}; {PublicKey.Item2})");
        public void ShowPrivateKey() =>
            Console.WriteLine($"Private key: ({PrivateKey.Item1}; {PrivateKey.Item2})\n");
    }
}
