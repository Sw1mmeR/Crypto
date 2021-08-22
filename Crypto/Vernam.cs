using System;
using System.Numerics;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Windows.Forms;
using System.Diagnostics;

namespace Crypto
{
    public static class Vernam
    {
        static Stopwatch stopWatch = new Stopwatch();
        static TimeSpan ts;
        private static BigInteger Key { get; set; }
        private static int _numberOfBytes { get; set; }
        public static void Init(int numberOfBytes = 256)
        {
            _numberOfBytes = numberOfBytes;
            Key = CryptoFunctions.GenerateRandomNumber(_numberOfBytes);
        }
        public static byte[] EncryptDecrypt(byte[] message)
        {
            BigInteger resultNumber = new BigInteger(message) ^ Key;
            return resultNumber.ToByteArray();
        }   
        public static Tuple<List<byte[]>, string> EncryptDecryptList(List<byte[]> message, bool decrypt = false, ProgressBar bar = null)
        {
            stopWatch.Start();

            List<byte[]> result = new List<byte[]>();
            bar.Value = 0;
            bar.Maximum = message.Count;

            foreach(var line in message)
            {
                result.Add(EncryptDecrypt(line));
                ++bar.Value;
            }
            if (decrypt)
                Init();

            stopWatch.Stop();
            ts = stopWatch.Elapsed;
            stopWatch.Reset();

            string elapsedTime = String.Format("{0:00}:{1:00}:{2:00}.{3:00}",
               ts.Hours, ts.Minutes, ts.Seconds,
               ts.Milliseconds / 10);

            return Tuple.Create(result, elapsedTime);
        }
        public static BigInteger GetKey()
            => Key;
        public static BigInteger SetKey(byte[] bytes)
            => Key = new BigInteger(bytes);
    }
}
