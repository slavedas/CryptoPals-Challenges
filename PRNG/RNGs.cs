using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AESTools;

namespace PRNG
{

    public class MT19937
    {
        private static int w = 32;
        private static int n = 624;
        private static int m = 397;
        private static int r = 31;
        private static uint a = 0x9908B0DF;
        private static int u = 11;
        private static uint d = 0xFFFFFFFF;
        private static int s = 7;
        private static uint b = 0x9D2C5680;
        private static int t = 15;
        private static uint c = 0xEFC60000;
        private static int l = 18;
        private static uint f = 1812433253;
        private static uint m_lowerMask = (uint)((1 << r) - 1);
        private static uint m_upperMask = 0xFFFFFFFF & ~m_lowerMask;

        private uint[] m_MT = null;
        private uint m_index = 0;

        private static MT19937 rand = null;

        public static bool CheckPasswordForRNG(string password)
        {
            UInt32 unixTimestamp = (UInt32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds;
            bool result = false;
            return result;
        }

        public static string Password(int length, bool resetSeed = false)
        {
            // Valid characters are 32-126
            // 126 - 32 = 94
            if (rand == null || resetSeed)
            {
                rand = new MT19937((UInt32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds);
            }
            byte[] result = new byte[length];
            for (int ii = 0; ii < length; ii += 4)
            {
                int len = Math.Min(4, length - ii);
                var randomBytes = rand.KeyStream();
                for (int jj = 0; jj < len; ++jj)
                {
                    result[ii + jj] = (byte)((randomBytes[jj] % 95) + 32);
                }
            }
            return Encoding.ASCII.GetString(result);
        }

        public static string Password2(int length, bool resetSeed=false)
        {
            // Valid characters are 32-126
            // 126 - 32 = 94
            if (rand == null || resetSeed)
            {
                rand = new MT19937((UInt32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds);
            }
            byte[] result = new byte[length];
            for (int ii = 0; ii < length; ii += 1)
            {
                var randomBytes = rand.Next();
                result[ii] = (byte)((randomBytes % 95) + 32);
            }
            return Encoding.ASCII.GetString(result);
        }

        public MT19937(uint seed=0)
        {
            m_MT = new uint[n];
            m_index = (uint)(n + 1);
            if (seed != 0)
            {
                Seed(seed);
            }
        }

        public MT19937(uint [] state, uint index)
        {
            m_MT = state;
            m_index = index;
        }

        public void Seed(uint seed)
        {
            m_index = (uint)n;
            m_MT[0] = seed;
            for (uint ii = 1; ii < n; ++ii)
            {
                m_MT[ii] = 0xFFFFFFFF & (f * (m_MT[ii - 1] ^ (m_MT[ii - 1] >> (w - 2))) + ii);
            }
        }

        public uint Next()
        {
            if (m_index >= n)
            {
                if (m_index > n)
                {
                    Seed(5489); //Reference C code constant seed if unseeded
                }
                Twist();
            }
            uint y = m_MT[m_index];
            y ^= ((y >> u) & d);
            y ^= ((y << s) & b);
            y ^= ((y << t) & c);
            y ^= (y >> l);

            m_index += 1;
            return 0xFFFFFFFF & y;
        }

        public byte [] KeyStream()
        {
            uint value = Next();
            return BitConverter.GetBytes(value);
        }

        private void Twist()
        {
            for (int ii = 0; ii < n; ++ii)
            {
                uint x = (m_MT[ii] & m_upperMask) + (m_MT[(ii + 1) % n] & m_lowerMask);
                uint xA = x >> 1;
                if (x % 2 != 0)
                {
                    xA ^= a;
                }
                m_MT[ii] = m_MT[(ii + m) % n] ^ xA;
            }
            m_index = 0;
        }

        internal static uint untemper(uint num)
        {
            //            uint y = m_MT[m_index];
            //            y = y ^ ((y >> u) & d); u = 11 d = FFFFFFFF
            //            y = y ^ ((y << s) & b); s = 7 b = 9D2C5680
            //            y = y ^ ((y << t) & c); t = 15 c = EFC60000
            //            y = y ^ (y >> l); l = 18
            //The top 18 bits were conserved so they are there to undo with an XOR
            //PseudoRandom Output
            uint y = num ^ (num >> l); // Validated
            // Value after (t,c) before ^ >> l
            y ^= ((y << t) & c); // Validated
            // Value after (s,b) before (t,c)
            // y ^= ((y << s) & b); have to work from zeroeth bit up one at a time.
            uint value = 0x1;
            for (int ii = 0; ii < 32; ++ii)
            {
                if (((value << s) & b) != 0)
                {
                    y ^= ((y << s) & (value << s));
                }
                value <<= 1;
            }
            // Value after (u, d)
            // y ^= ((y >> u) & d); Same thing but starting at bit 31
            value = 0x1;
            value <<= 31;
            for (int ii = 31; ii > 0; --ii)
            {
                y ^= ((y >> u) & (value >> u));
                value >>= 1;
            }

            // m_MT[index]
            return y;
        }
    }

    class StreamCipher
    {
        private UInt16 m_seed;
        private MT19937 m_encryptRandom = null;
        private MT19937 m_decryptRandom = null;
        public void PrintSeed()
        {
            Console.WriteLine("Random Seed: " + m_seed);
        }
        public StreamCipher()
            : this((UInt16)new Random().Next(65536))
        {
        }

        public StreamCipher(UInt16 seed)
        {
            m_seed = seed;
            Init();
        }

        StreamCipher(StreamCipher copy)
            : this(copy.m_seed)
        {
        }
        private void Init()
        {
            m_encryptRandom = new MT19937(m_seed);
            m_decryptRandom = new MT19937(m_seed);
        }

        public byte [] Encrypt(byte [] plaintext)
        {
            return doEncrypt(plaintext, m_encryptRandom);
        }
        public byte[] Decrypt(byte[] ciphertext)
        {
            return doEncrypt(ciphertext, m_decryptRandom);
        }

        private byte [] doEncrypt(byte [] text, MT19937 random)
        {
            byte[] outText = new byte[text.Length];
            for (int ii = 0; ii < text.Length; ii += 4)
            {
                int len = Math.Min(4, text.Length - ii);
                byte[] block = new byte[len];
                Buffer.BlockCopy(text, ii, block, 0, block.Length);
                byte[] xorBlock = random.KeyStream();
                for (int jj = 0; jj < block.Length; ++jj)
                {
                    block[jj] ^= xorBlock[jj];
                }
                Buffer.BlockCopy(block, 0, outText, ii, block.Length);
            }
            return outText;
        }

    }
    class RNGs
    {
        static void TestMT19937Seed()
        {
            Random systemRand = new Random();
            int sleepTime = systemRand.Next(961) + 40;
            //System.Threading.Thread.Sleep(sleepTime * 1000);
            UInt32 unixTimestamp = (UInt32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds - (uint)sleepTime;
            MT19937 prng = new MT19937(unixTimestamp);
            sleepTime = systemRand.Next(961) + 40;
            //System.Threading.Thread.Sleep(sleepTime * 1000);
            uint random_Number = prng.Next();

            var unixTimestamp2 = (UInt32)(DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1))).TotalSeconds + (uint)sleepTime;
            uint rNum2 = 0;
            while (rNum2 != random_Number)
            {
                unixTimestamp2 -= 1;
                prng.Seed(unixTimestamp2);
                rNum2 = prng.Next();
            }
            Console.WriteLine("Timestamp: " + unixTimestamp + " Random Number: " + random_Number + " Guessed Seed: " + unixTimestamp2 + " New Random Number: " + rNum2);
        }
        private static void UntemperTest()
        {
            MT19937 rand = new MT19937();
            uint[] state = new uint[624];
            for (int ii = 0; ii < 624; ++ii)
            {
                state[ii] = MT19937.untemper(rand.Next());
            }
            MT19937 rand2 = new MT19937(state, 624);
            for (int ii = 0; ii < 30; ++ii)
            {
                Console.WriteLine("Rand1: " + rand.Next() + " Rand2: " + rand2.Next());
            }

        }
        static byte [] StreamOracle(string knownPlaintext)
        {
            Random rand = new Random();
            int bytesToAppend = rand.Next(623 * 4);
            byte[] plainText = new byte[bytesToAppend];
            rand.NextBytes(plainText);
            plainText = Utilities.Concatenate(plainText, Encoding.ASCII.GetBytes(knownPlaintext));
            StreamCipher sc = new StreamCipher();
            sc.PrintSeed();
            return sc.Encrypt(plainText);
        }
        static void StreamCipherTest()
        {
            StreamCipher sc = new StreamCipher();
            byte[] plaintext = Encoding.ASCII.GetBytes("The way to a man's heart is through his sternum.");
            byte[] cipherText = sc.Encrypt(plaintext);
            byte[] plaintext2 = sc.Decrypt(cipherText);

            Console.WriteLine("Original Plaintext: " + Encoding.ASCII.GetString(plaintext));
            Console.WriteLine("Ciphertext: " + Encoding.ASCII.GetString(cipherText));
            Console.WriteLine("Recovered Plaintext: " + Encoding.ASCII.GetString(plaintext2));
        }

        static void SeedFinding()
        {
            string knownPlaintext = "AAAAAAAAAAAAAA";
            var cipherText = StreamOracle("AAAAAAAAAAAAAA");
            int randomBytes = cipherText.Length - knownPlaintext.Length;
            int extra = cipherText.Length % 4;
            int start = cipherText.Length - extra - 8; // the last 8 bytes aligned to the rng
            byte[] xorBlock = new byte[8];
            Buffer.BlockCopy(cipherText, start, xorBlock, 0, xorBlock.Length);
            int kptStart = knownPlaintext.Length - extra - xorBlock.Length;
            for (int ii = 0; ii < xorBlock.Length; ++ii)
            {
                xorBlock[ii] ^= (byte)knownPlaintext[kptStart + ii];
            }
            uint value1 = (UInt32)BitConverter.ToInt32(xorBlock, 0);
            uint value2 = (UInt32)BitConverter.ToInt32(xorBlock, 4);
            // We now have our anchor values run through our possible seeds until 
            // we find the anchor values at the right starting position
            for (uint ii = 0; ii < 65536; ++ii)
            {
                MT19937 rng = new MT19937(ii);
                for (int jj = 0; jj < start/4; ++jj)
                {
                    rng.Next();
                }
                if (value1 == rng.Next() && value2 == rng.Next())
                {
                    Console.WriteLine("RNG Seed: " + ii);
                    break;
                }
            }

        }

        static void PasswordTest()
        {
            List<string> passwords = new List<string>(100);
            for (int ii = 0; ii < 100; ++ii)
            {
                passwords.Add(MT19937.Password(16));
            }
            System.Threading.Thread.Sleep(5000);
            List<string> passwords2 = new List<string>(100);
            for (int ii = 0; ii < 100; ++ii)
            {
                if (ii == 0)
                {
                    passwords2.Add(MT19937.Password2(16, resetSeed:true));
                }
                else
                {
                    passwords2.Add(MT19937.Password2(16));
                }
            }
            System.Threading.Thread.Sleep(5000);
            foreach (var pw in passwords)
            {
                //if (CheckPasswordForRNG(pw)) ;
            }
        }

        static void Main(string[] args)
        {
            //TestMT19937Seed();
            //UntemperTest();
            //SeedFinding();
            PasswordTest();
        }

    }
}
