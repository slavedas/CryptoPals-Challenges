using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Threading.Tasks;
using System.Security.Cryptography;
using CryptoChallenge;
using KeyUtils;
using XORFunctions;

namespace AESTools
{
    public class PKCS7Padding
    {
        public static byte[] Pad(byte [] input, int blockSize)
        {
            int padTo = input.Length + (blockSize - (input.Length % blockSize));
            if (padTo == input.Length)
            {
                padTo += blockSize;
            }
            byte[] result = new byte[padTo];
            Array.Copy(input, result, input.Length);
            byte padByte = (byte)(padTo - input.Length);
            for (int ii = input.Length; ii < result.Length; ++ii)
            {
                result[ii] = padByte;
            }
            return result;
        }

        public static byte[] Unpad(byte[] input)
        {
            byte padLength = input[input.Length - 1];
            if (!ValidPad(input))
            {
                throw new InvalidDataException("Padding value of " + input.Last() + " is not valid.");
            }
            byte[] result = new byte[input.Length - padLength];
            System.Buffer.BlockCopy(input, 0, result, 0, result.Length);
            return result;
        }

        internal static bool ValidPad(byte[] plaintext)
        {
            byte padLength = plaintext.Last();
            if (padLength > 16)
            {
                return false;
            }
            for (int ii = plaintext.Length - padLength; ii < plaintext.Length; ++ii)
            {
                if (plaintext[ii] != padLength)
                {
                    return false;
                }
            }
            return true;
        }
    }
    public class Utilities
    {

        public static byte[] Concatenate(byte [] lhs, byte[] rhs)
        {
            byte[] comb = new byte[lhs.Length + rhs.Length];
            System.Buffer.BlockCopy(lhs, 0, comb, 0, lhs.Length);
            System.Buffer.BlockCopy(rhs, 0, comb, lhs.Length, rhs.Length);
            return comb;
        }
        public static byte[] GenerateRandomKey()
        {
            byte[] key = new byte[16];
            Random r = new Random();
            r.NextBytes(key);
            return key;
        }

        public static byte[] GetGlobalKey()
        {
            if (g_key == null)
            {
                g_key = GenerateRandomKey();
            }
            return g_key;
        }
        public static byte[] EncryptedProfile_For(string email, ref byte[] key)
        {
            if (key == null)
            {
                key = GetGlobalKey();
            }
            string profile = StringBaseConversion.profile_for(email);
            return ECB.Encrypt(Aes.Create(), Encoding.ASCII.GetBytes(profile), key, new byte[16], last:true);
        }

        static List<byte> lastCharList = null;
        public static Dictionary<string, byte> CreateLastCharDictionary(int blocksize, string knownchars)
        {
            if (lastCharList == null)
            {
                lastCharList = new List<byte>();
                for (byte ii = 1; ii < 127; ++ii)
                {
                    lastCharList.Add(ii);
                }
//                for (byte ii = 32; ii < 126; ++ii)
//                {
//                    lastCharList.Add(ii);
//                }
            }
            Dictionary<string, byte> result = new Dictionary<string, byte>();
            var knownLength = knownchars.Length;
            var constLength = blocksize - knownLength - 1;
            byte[] knownBytes = Enumerable.Repeat((byte)'A', constLength).ToArray();
            string knownBlock = ASCIIEncoding.ASCII.GetString(knownBytes);
            byte [] resultBlock = new byte[blocksize];
            foreach (var value in lastCharList)
            {
                string plaintext = knownBlock + knownchars + (char)value;
                var cipherText = ECB_EncryptionOracle(ASCIIEncoding.ASCII.GetBytes(plaintext));
                System.Buffer.BlockCopy(cipherText, 0, resultBlock, 0, blocksize);
                string resultStr = ASCIIEncoding.ASCII.GetString(resultBlock);
                result[resultStr] = value;
            }
            return result;
        }

        public static Tuple<byte[], bool> ECB_CBC_EncryptionOracle(byte[] plaintext)
        {
            byte[] result = null;
            Random rand = new Random();
            int pad = rand.Next(6) + 5;
            int rNum = rand.Next(100);
            bool ecb = (rNum >= 50);
            Aes aes = Aes.Create();
            byte[] padBytes = new byte[pad];
            rand.NextBytes(padBytes);
            byte[] paddedText = new byte[padBytes.Length * 2 + plaintext.Length];
            System.Buffer.BlockCopy(padBytes, 0, paddedText, 0, padBytes.Length);
            System.Buffer.BlockCopy(plaintext, 0, paddedText, padBytes.Length, plaintext.Length);
            System.Buffer.BlockCopy(padBytes, 0, paddedText, padBytes.Length + plaintext.Length, padBytes.Length);
            plaintext = paddedText;
            if (ecb)
            {
                result = ECB.Encrypt(aes, plaintext, GenerateRandomKey(), new byte[16]);
            }
            else
            {
                result = CBC.Encrypt(plaintext, GenerateRandomKey(), GenerateRandomKey());
            }
            return new Tuple<byte[], bool>(result, ecb);
        }
        public static byte[] g_key = null;
        public static byte[] g_unknownText = null;
        public static byte[] g_randomPrefix = null;
        public static byte[] ECB_EncryptionOracle(byte[] plaintext)
        {
            if (g_key == null)
            {
                g_key = GenerateRandomKey();
            }

            byte[] result = null;
            Aes aes = Aes.Create();
            if (g_unknownText != null)
            {
                byte[] paddedText = new byte[g_unknownText.Length + plaintext.Length];
                System.Buffer.BlockCopy(plaintext, 0, paddedText, 0, plaintext.Length);
                System.Buffer.BlockCopy(g_unknownText, 0, paddedText, plaintext.Length, g_unknownText.Length);
                plaintext = paddedText;
            }
            result = ECB.Encrypt(aes, plaintext, g_key, new byte[16]);
            return result;
        }
        public static byte[] ECB_EncryptionOracleHard(byte[] plaintext)
        {
            if (g_key == null)
            {
                g_key = GenerateRandomKey();
            }
            if (g_randomPrefix == null)
            {
                Random rand = new Random();
                int bytes = rand.Next(1000);
                g_randomPrefix = new byte[bytes];
                rand.NextBytes(g_randomPrefix);
            }

            byte[] result = null;
            Aes aes = Aes.Create();
            if (g_unknownText != null)
            {
                byte[] paddedText = new byte[g_randomPrefix.Length + g_unknownText.Length + plaintext.Length];
                int offset = 0;
                System.Buffer.BlockCopy(g_randomPrefix, 0, paddedText, 0, g_randomPrefix.Length);
                offset += g_randomPrefix.Length;
                System.Buffer.BlockCopy(plaintext, 0, paddedText, offset, plaintext.Length);
                offset += plaintext.Length;
                System.Buffer.BlockCopy(g_unknownText, 0, paddedText, offset, g_unknownText.Length);
                plaintext = paddedText;
            }
            result = ECB.Encrypt(aes, plaintext, g_key, new byte[16]);
            return result;
        }

    }
    public class ECB
    {
        public static byte[] Encrypt(Aes aes, byte [] plainText, byte [] key, byte [] IV, bool last=false)
        {
            if (key == null)
            {
                key = Utilities.g_key;
            }
            if (last || plainText.Length % 16 != 0)
            {
                plainText = PKCS7Padding.Pad(plainText, 16);
            }
            if (last)
            {
                byte[] padText = new byte[plainText.Length + (aes.BlockSize / 8)];
                System.Buffer.BlockCopy(plainText, 0, padText, 0, plainText.Length);
                System.Buffer.BlockCopy((byte[])Enumerable.Repeat((byte)(aes.BlockSize / 8), (aes.BlockSize / 8)).ToArray(), 0, padText, plainText.Length, (aes.BlockSize / 8));
                plainText = padText;
            }

            aes.Mode = CipherMode.ECB;
            aes.BlockSize = 128;
            aes.KeySize = 128;
            aes.Key = key;
            aes.IV = IV;
            aes.Padding = PaddingMode.None;
            ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
            byte[] cipherText = new byte[plainText.Length];
            for (int ii = 0; ii < plainText.Length; ii += 16)
            {
                int val = encryptor.TransformBlock(plainText, ii, 16, cipherText, ii);
            }
            encryptor.Dispose();
            return cipherText;
        }

        public static byte[] Decrypt(Aes aesEngine, byte[] cipherText, byte[] key, byte[] IV, bool last = false)
        {
            if (key == null)
            {
                key = Utilities.g_key;
            }
            aesEngine.Mode = CipherMode.ECB;
            aesEngine.BlockSize = 128;
            aesEngine.KeySize = 128;
            aesEngine.Key = key;
            aesEngine.IV = IV;
            aesEngine.Padding = PaddingMode.None;
            ICryptoTransform decryptor = aesEngine.CreateDecryptor(aesEngine.Key, aesEngine.IV);
            byte[] plainText = new byte[cipherText.Length];
            var result = decryptor.TransformBlock(cipherText, 0, cipherText.Length, plainText, 0);
            //var plainText = decryptor.TransformFinalBlock(cipherText, 0, cipherText.Length);
            decryptor.Dispose();
            if (last)
            {
                plainText = PKCS7Padding.Unpad(plainText);
            }
            return plainText;
        }
        public delegate byte[] EncryptOracleDelegate(byte[] plaintext);

        public static byte[] KnownPlaintextOracleDecrypt(EncryptOracleDelegate EncryptFunction, int keysize=16, int offset=0, int start=0)
        {
            byte[] plaintext = null;
            byte[] block = new byte[keysize];
            Console.WriteLine("Encrypted with AES 128 ECB");
            string knownChars = "";
            string final_plaintext = "";
            byte[] cipherText = null;
            do
            {
                for (int ii = 1; ii <= keysize; ++ii)
                {
                    var lcdict = Utilities.CreateLastCharDictionary(keysize, knownChars);
                    string knownBlock = "";
                    if (ii < keysize + offset)
                    {
                        knownBlock = ASCIIEncoding.ASCII.GetString((byte[])Enumerable.Repeat((byte)'A', keysize - ii + offset).ToArray());
                    }
                    cipherText = EncryptFunction(ASCIIEncoding.ASCII.GetBytes(knownBlock));
                    System.Buffer.BlockCopy(cipherText, start, block, 0, keysize);
                    string resultStr = ASCIIEncoding.ASCII.GetString(block);
                    byte lastChar = 0;
                    try
                    {
                        lastChar = lcdict[resultStr];
                    }
                    catch
                    {
                        break;
                    }
                    final_plaintext += (char)lastChar;
                    knownChars += (char)lastChar;
                    if (knownChars.Length == keysize)
                    {
                        knownChars = knownChars.Substring(1);
                    }
                }
                start += keysize;
            } while (start < cipherText.Length);
            plaintext = Encoding.ASCII.GetBytes(final_plaintext);
            return PKCS7Padding.Unpad(plaintext);
        }
    }

    public class CBC
    {
        public static byte[] CookieSandwichMaker(string arbitraryString)
        {
            int pos = arbitraryString.IndexOf(";");
            string sanitizedString = "";
            while (pos != -1)
            {
                sanitizedString = arbitraryString.Substring(0, pos) + "\";\"";
                arbitraryString = arbitraryString.Substring(pos + 1, arbitraryString.Length - (pos + 1));
                pos = arbitraryString.IndexOf(";");
            }
            pos = arbitraryString.IndexOf("=");
            while (pos != -1)
            {
                sanitizedString = arbitraryString.Substring(0, pos) + "\"=\"";
                arbitraryString = arbitraryString.Substring(pos + 1, arbitraryString.Length - (pos + 1));
                pos = arbitraryString.IndexOf("=");
            }
            sanitizedString += arbitraryString;
            byte[] result = PKCS7Padding.Pad(Encoding.ASCII.GetBytes("comment1=cooking%20MCs;userdata=" + sanitizedString + ";comment2=%20like%20a%20pound%20of%bacon"), 16);
            return Encrypt(result, null, new byte[16]);
        }

        public static byte[] Encrypt(byte[] plaintext, byte[] key, byte[] IV)
        {
            if (key == null)
            {
                if (Utilities.g_key == null)
                {
                    Utilities.g_key = Utilities.GenerateRandomKey();
                }
                key = Utilities.g_key;
            }
            var blockLength = 16;
            if (plaintext.Length % blockLength != 0 || !PKCS7Padding.ValidPad(plaintext))
            {
                plaintext = PKCS7Padding.Pad(plaintext, blockLength);
            }
            byte[] cipherText = null;
            byte[] block = new byte[blockLength];
            byte[] lastCipherBlock = IV;
            IV = new byte[blockLength];
            Aes aes = Aes.Create();
            for (int ii = 0; ii <= plaintext.Length - blockLength; ii += blockLength)
            {
                Array.Copy(plaintext, ii, block, 0, blockLength);
                block = ByteArrayXOR.FixedXOR(lastCipherBlock, block);
                lastCipherBlock = ECB.Encrypt(aes, block, key, IV);
                if (cipherText == null)
                {
                    cipherText = new byte[lastCipherBlock.Length];
                    lastCipherBlock.CopyTo(cipherText, 0);
                }
                else
                {
                    byte[] newCT = new byte[cipherText.Length + lastCipherBlock.Length];
                    System.Buffer.BlockCopy(cipherText, 0, newCT, 0, cipherText.Length);
                    System.Buffer.BlockCopy(lastCipherBlock, 0, newCT, cipherText.Length, lastCipherBlock.Length);
                    cipherText = newCT;
                }
            }
            return cipherText;
        }

        public static byte[] Decrypt(byte[] cipherText, byte[] key, byte[] IV)
        {
            var blockLength = 16;
            byte[] plaintext = null;
            byte[] block = new byte[blockLength];
            byte[] xorBlock = new byte[blockLength];
            byte[] lastCipherBlock = IV;
            IV = new byte[blockLength];
            Aes aes = Aes.Create();
            for (int ii = 0; ii < cipherText.Length; ii += blockLength)
            {
                Array.Copy(cipherText, ii, block, 0, blockLength);
                lastCipherBlock.CopyTo(xorBlock, 0);
                lastCipherBlock = block;
                block = ECB.Decrypt(aes, block, key, IV);
                block = ByteArrayXOR.FixedXOR(block, xorBlock);
                if (plaintext == null)
                {
                    plaintext = new byte[block.Length];
                    System.Buffer.BlockCopy(block, 0, plaintext, 0, block.Length);
                }
                else
                {
                    byte[] newPT = new byte[plaintext.Length + block.Length];
                    System.Buffer.BlockCopy(plaintext, 0, newPT, 0, plaintext.Length);
                    System.Buffer.BlockCopy(block, 0, newPT, plaintext.Length, block.Length);
                    plaintext = newPT;
                }
            }
            return plaintext;
        }

        private static List<string> OracleStrings = null;
        public static Tuple<byte[], byte[]> PaddingOracle()
        {
            if (OracleStrings == null)
            {
                OracleStrings = new List<string>(10);
                StreamReader fin = new StreamReader(new FileStream("C:/Users/stephen.lavedas/Downloads/CryptoChallenge17.txt", FileMode.Open));
                while (!fin.EndOfStream)
                {
                    string line = fin.ReadLine();
                    OracleStrings.Add(line);
                }
            }
            Random rand = new Random();
            string selectedLine = OracleStrings[rand.Next(10)];
            byte[] plainText = Convert.FromBase64CharArray(selectedLine.ToCharArray(), 0, selectedLine.Length);
            byte[] iv = Utilities.GenerateRandomKey(); //Keys are 16 bytes, IV is 16 bytes
            var cipherText = Encrypt(plainText, Utilities.GetGlobalKey(), iv);
            return new Tuple<byte[], byte[]>(cipherText, iv);
        }

        public static bool PaddingOracleDecrypt(byte[] cipherText, byte[] iv)
        {
            try
            {
                Decrypt(cipherText, Utilities.GetGlobalKey(), iv);
            }
            catch
            {
                return false;
            }
            return true;
        }
    }

    public class CTR
    {
        public static byte[] CookieSandwichMaker(string arbitraryString, Stream cstream)
        {
            int pos = arbitraryString.IndexOf(";");
            string sanitizedString = "";
            while (pos != -1)
            {
                sanitizedString = arbitraryString.Substring(0, pos) + "\";\"";
                arbitraryString = arbitraryString.Substring(pos + 1, arbitraryString.Length - (pos + 1));
                pos = arbitraryString.IndexOf(";");
            }
            pos = arbitraryString.IndexOf("=");
            while (pos != -1)
            {
                sanitizedString = arbitraryString.Substring(0, pos) + "\"=\"";
                arbitraryString = arbitraryString.Substring(pos + 1, arbitraryString.Length - (pos + 1));
                pos = arbitraryString.IndexOf("=");
            }
            sanitizedString += arbitraryString;
            byte[] result = Encoding.ASCII.GetBytes("comment1=cooking%20MCs;userdata=" + sanitizedString + ";comment2=%20like%20a%20pound%20of%bacon");
            return cstream.Encrypt(result, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
        }

        public class Stream
        {
            #region Member Variables
            private byte[] m_key = new byte[16];
            private List<byte[]> m_nonces = new List<byte[]>();
            private UInt64 m_counter = 0;
            #endregion

            public Stream(byte[] key)
            {
                if (key == null)
                {
                    key = Utilities.GetGlobalKey();
                }
                InitializeStream(key);
            }
            public Stream()
                : this(Utilities.GetGlobalKey())
            {
            }
            private void InitializeStream(byte[] key)
            {
                System.Buffer.BlockCopy(key, 0, m_key, 0, m_key.Length);
                m_counter = 0;
                m_nonces.Clear();
            }

            public void Edit(ref byte[] cipherText, UInt64 offset, byte [] newText)
            {
                Edit(ref cipherText, m_key, offset, newText);
            }
            private void Edit(ref byte[] cipherText, byte[] key, UInt64 offset, byte[] newText)
            {
                UInt64 off_counter = offset / 16; // Starting block
                UInt64 counter_end = (offset + (UInt64)newText.Length) / 16; //Ending block
                if (counter_end == off_counter)
                {
                    counter_end += 1; //This should let us run through the loop once
                }
                int off_rem = (int)(offset % 16);
                byte[] xorKey = new byte[newText.Length];

                int start = 0;
                for (UInt64 ii = off_counter; ii < counter_end; ii += 1)
                {
                    byte[] keyText = new byte[16];
                    System.Buffer.BlockCopy(m_nonces[(int)ii], 0, keyText, 0, 8);
                    System.Buffer.BlockCopy(BitConverter.GetBytes(ii), 0, keyText, 8, 8);
                    var tmpKey = ECB.Encrypt(Aes.Create(), keyText, m_key, new byte[16]);
                    if (offset > ii * 16)
                    {
                        System.Buffer.BlockCopy(tmpKey, off_rem, xorKey, 0, 16 - off_rem);
                        start += 16 - off_rem;
                    }
                    else
                    {
                        int len = Math.Min(16, xorKey.Length - start);
                        Buffer.BlockCopy(tmpKey, 0, xorKey, start, len);
                    }
                }
                var newCipherText = ByteArrayXOR.FixedXOR(xorKey, newText);
                Buffer.BlockCopy(newCipherText, 0, cipherText, (int)offset, newCipherText.Length);
            }

            private byte[] EncryptBlock(byte[] plaintext, byte[] nonce)
            {
                if (plaintext.Length > 16)
                {
                    throw new ArgumentException("Calls to EncryptBlock must be 16 bytes or less");
                }
                if (nonce == null)
                {
                    throw new ArgumentNullException("Nonce must be non-null.");
                }
                if (nonce.Length < 8)
                {
                    throw new ArgumentException("The nonce is too short.  Must be 8 bytes long");
                }
                m_nonces.Add(nonce);
                byte[] keyText = new byte[16];
                System.Buffer.BlockCopy(nonce, 0, keyText, 0, 8);
                System.Buffer.BlockCopy(BitConverter.GetBytes(m_counter), 0, keyText, 8, 8);
                byte[] xorKey = ECB.Encrypt(Aes.Create(), keyText, m_key, new byte[16]);
                m_counter += 1;
                if (plaintext.Length < 16)
                {
                    byte[] shortXorKey = new byte[plaintext.Length];
                    Buffer.BlockCopy(xorKey, 0, shortXorKey, 0, shortXorKey.Length);
                    xorKey = shortXorKey;
                }
                return XORFunctions.ByteArrayXOR.FixedXOR(xorKey, plaintext);
            }

            public byte[] Encrypt(byte [] plainText, byte [] nonce)
            {
                byte[] ciphertext = new byte[plainText.Length];
                for (int ii = 0; ii < plainText.Length; ii += 16)
                {
                    int length = Math.Min(16, plainText.Length - ii);
                    byte[] block = new byte[length];
                    Buffer.BlockCopy(plainText, ii, block, 0, length);
                    block = EncryptBlock(block, nonce);
                    Buffer.BlockCopy(block, 0, ciphertext, ii, length);
                }
                return ciphertext;
            }
            public byte[] Decrypt(byte[] cipherText, byte[] nonce)
            {
                return Encrypt(cipherText, nonce);
            }

        }
    }

    class AESCode
    {
        public static bool FindAdminTrue(string input)
        {
            return input.IndexOf(";admin=true;") != -1;
        }

        static void AES_CBC_Test()
        {
            string testString = "What dreams may come?";
            string key = "YELLOW SUBMARINE";
            var ptBytes = ASCIIEncoding.ASCII.GetBytes(testString);
            var kBytes = ASCIIEncoding.ASCII.GetBytes(key);
            byte[] iv = new byte[16];
            var cipherText = CBC.Encrypt(ptBytes, kBytes, iv);
            //iv = new byte[32];
            var plainText = CBC.Decrypt(cipherText, kBytes, iv);
            Console.WriteLine("Plaintext: " + ASCIIEncoding.ASCII.GetString(plainText));
            var buffer = StringBaseConversion.Base64FileToByteArray("C:/Users/stephen.lavedas/Downloads/CryptoChallenge10.txt");
            plainText = CBC.Decrypt(buffer, kBytes, iv);
            Console.WriteLine("Plaintext: " + ASCIIEncoding.ASCII.GetString(plainText));

        }

        static void AES_ECB_DecryptTest()
        {
            byte[] rawBytes = StringBaseConversion.Base64FileToByteArray("C:/Users/stephen.lavedas/Downloads/CryptoChallenge7.txt");
            byte[] iv = new byte[16];
            byte[] key = ASCIIEncoding.ASCII.GetBytes("YELLOW SUBMARINE");
            Aes aesEngine = Aes.Create();
            var plaintextBytes = ECB.Decrypt(aesEngine, rawBytes, key, iv, last:true);
            Console.WriteLine("Plaintext: " + ASCIIEncoding.ASCII.GetString(plaintextBytes));
            return;
        }

        static public int ECBDetect(byte [] cipherText, int blockSize)
        {
            byte[] currentBlock = new byte[blockSize];
            byte[] testBlock = new byte[blockSize];
            int count = 0;
            for (int ii = 0; ii < cipherText.Length - (blockSize * 2); ii += blockSize)
            {
                Array.Copy(cipherText, ii, currentBlock, 0, blockSize);
                for (int jj = ii + blockSize; jj < cipherText.Length - blockSize; jj += blockSize)
                {
                    Array.Copy(cipherText, jj, testBlock, 0, blockSize);
                    var distance = Hamming.CalculateHammingDistance(currentBlock, testBlock);
                    if (distance == 0)
                    {
                        count += 1;
                    }
                }
            }
            return count;
        }

        static public bool ECB_CBC_Detect(byte [] cipherText, int blockSize)
        {
            var block1 = new byte[blockSize];
            var block2 = new byte[blockSize];
            int ecbSum = 0;
            int cbcSum = 0;
            System.Buffer.BlockCopy(cipherText, 0, block1, 0, blockSize);
            System.Buffer.BlockCopy(cipherText, blockSize, block2, 0, blockSize);
            var ecbHammingDiff = KeyUtils.Hamming.CalculateHammingDistance(block1, block2);
            ecbSum += ecbHammingDiff;
            var cbcHammingDiff = KeyUtils.Hamming.CalculateHammingDistance(block1, XORFunctions.ByteArrayXOR.FixedXOR(block1, block2));
            cbcSum += cbcHammingDiff;
            return (ecbSum < cbcSum);
        }
        static void ECBDetectionTest()
        {
            StreamReader fin = new StreamReader("C:/Users/stephen.lavedas/Downloads/CryptoChallenge8.txt");
            int lineCount = 0;
            while (!fin.EndOfStream)
            {
                string line = fin.ReadLine();
                byte[] rawBytes = StringBaseConversion.HexStringToByteArray(line);
                var count = ECBDetect(rawBytes, 16);
                if (count != 0)
                {
                    Console.WriteLine("Line: " + lineCount + " Contents: " + line + " has " + count + " Identical blocks.");
                }
                ++lineCount;
            }
        }

        static void ECB_CBC_DetectionTest()
        {
            byte[] plaintext = ASCIIEncoding.ASCII.GetBytes("YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE");
            for (int ii = 0; ii < 1000; ++ii)
            {
                var result = Utilities.ECB_CBC_EncryptionOracle(plaintext);
                bool ecb = (ECBDetect(result.Item1, 16) > 0);
                if (ecb)
                {
                    Console.Write("Detected as ECB");
                }
                else
                {
                    Console.Write("Detected as CBC");
                }
                if (result.Item2)
                {
                    Console.WriteLine(" Encrypted as ECB");
                }
                else
                {
                    Console.WriteLine(" Encrypted as CBC");
                }

            }
        }

        static void ECBSingleByteDecryptionTest()
        {
            Utilities.g_unknownText = StringBaseConversion.Base64FileToByteArray("C:/Users/stephen.lavedas/Downloads/CryptoChallenge12.txt");
            Dictionary<int, double> keySizeFreq = new Dictionary<int, double>();
            byte[] cipherText = null;
            for (int ii = 1; ii <= 64; ++ii)
            {
                byte[] prepend = Enumerable.Repeat((byte)'A', ii).ToArray();
                cipherText = Utilities.ECB_EncryptionOracle(prepend);
                var keysizes = KeyTools.FindMostLikelyKeysize(cipherText, keysizesToReturn: 4);
                int count = 1;
                foreach (var size in keysizes)
                {
                    if (!keySizeFreq.ContainsKey(size))
                    {
                        keySizeFreq[size] = 1.0/count; 
                    }
                    else
                    {
                        keySizeFreq[size] += 1.0/count;
                    }
                    ++count;
                }
            }
            var sortedKeys = keySizeFreq.OrderBy(x => x.Value).Reverse().ToArray();
            var keysize = sortedKeys[0].Key;
            Console.WriteLine("Keysize = " + keysize);
            byte[] plaintext = Enumerable.Repeat((byte)'A', keysize * 2).ToArray();
            cipherText = Utilities.ECB_EncryptionOracle(plaintext);
            bool ecb = (ECBDetect(cipherText, keysize) > 0);
            if (ecb)
            {
                plaintext = ECB.KnownPlaintextOracleDecrypt(Utilities.ECB_EncryptionOracle, keysize);
                Console.WriteLine("Plaintext: " + Encoding.ASCII.GetString(plaintext));
            }

        }
        static void ECBSingleByteDecryptionHardTest()
        {
            ECB.EncryptOracleDelegate EncryptFunction = Utilities.ECB_EncryptionOracleHard;
            Utilities.g_unknownText = StringBaseConversion.Base64FileToByteArray("C:/Users/stephen.lavedas/Downloads/CryptoChallenge12.txt");
            Dictionary<int, double> keySizeFreq = new Dictionary<int, double>();
            byte[] cipherText = null;
            for (int ii = 1; ii <= 128; ++ii)
            {
                byte[] prepend = Enumerable.Repeat((byte)'A', ii).ToArray();
                cipherText = Utilities.ECB_EncryptionOracleHard(prepend);
                var keysizes = KeyTools.FindMostLikelyKeysize(cipherText, keysizesToReturn: 4);
                int count = 1;
                foreach (var size in keysizes)
                {
                    if (!keySizeFreq.ContainsKey(size))
                    {
                        keySizeFreq[size] = 1.0 / count;
                    }
                    else
                    {
                        keySizeFreq[size] += 1.0 / count;
                    }
                    ++count;
                }
            }
            var sortedKeys = keySizeFreq.OrderBy(x => x.Value).Reverse().ToArray();
            var keysize = sortedKeys[0].Key;
            Console.WriteLine("Keysize = " + keysize);
            // Needs to be 3 blocks long since the swing is 0-15 bytes offset due to the unknown prefix
            // length.  To guarantee at least two blocks of the same content, you must be able to eat up to 
            // 15 bytes of intrusion.
            byte[] plaintext = Enumerable.Repeat((byte)'A', keysize * 3).ToArray();
            cipherText = EncryptFunction(plaintext);
            bool ecb = (ECBDetect(cipherText, keysize) > 0);
            byte [] block = new byte[keysize];
            if (ecb)
            {
                // Let's find out how big the random-prefix is
                // Starting at 1 block size, start trying to find the example block in the data
                // When it shows up, subtract 16 from the size of the plaintext we inserted and
                // subtract that from the position returned and we have the length of the prefix
                var cipherExample = ECB.Encrypt(Aes.Create(), (byte[])Enumerable.Repeat((byte)'A', keysize).ToArray(), Utilities.g_key, new byte[keysize]);
                int ptSize = keysize - 1; //To make the loop simpler.  We still start with ptSize == keysize for the first evaluation
                int matchLocation = -1;
                while (matchLocation == -1)
                {
                    ++ptSize;
                    plaintext = Enumerable.Repeat((byte)'A', ptSize).ToArray();
                    cipherText = EncryptFunction(plaintext);
                    matchLocation = Hamming.FindHammingMatch(cipherText, cipherExample);
                }
                ptSize -= keysize;
                int prefixSize = matchLocation - ptSize;
                Console.WriteLine("Encrypted with AES 128 ECB and a Prefix size of " + prefixSize);

                plaintext = ECB.KnownPlaintextOracleDecrypt(EncryptFunction, keysize, offset: ptSize, start: matchLocation);
                Console.WriteLine("Plaintext: " + Encoding.ASCII.GetString(plaintext));
                /*
                string knownChars = "";
                for (int ii = 1; ii <= keysize; ++ii)
                {
                    var lcdict = Utilities.CreateLastCharDictionary(keysize, knownChars);
                    string knownBlock = "";
                    if (ii < keysize + ptSize)
                        knownBlock = ASCIIEncoding.ASCII.GetString((byte[])Enumerable.Repeat((byte)'A', keysize - ii + ptSize).ToArray());
                    cipherText = EncryptFunction(ASCIIEncoding.ASCII.GetBytes(knownBlock));
                    System.Buffer.BlockCopy(cipherText, matchLocation, block, 0, keysize);
                    string resultStr = ASCIIEncoding.ASCII.GetString(block);
                    byte lastChar = lcdict[resultStr];
                    knownChars += (char)lastChar;
                }
                */
            }

        }

        static void ECB_CopyPasteTest()
        {
            byte[] key = null;
            byte[] eProfile = Utilities.EncryptedProfile_For("m@me.com", ref key); //sets g_key for the future
            //"email=m@me.com&uid=10&role=user"
            // 0123456789ABCDEF0123456789ABCDEF
            //Encrypt id=10&role=admin with the same key.  Copy and replace into the cipertext
            byte[] eRole = ECB.Encrypt(Aes.Create(), Encoding.ASCII.GetBytes("id=10&role=admin"), key, new byte[16], last:true);
            byte[] newProfile = new byte[16 + eRole.Length];
            System.Buffer.BlockCopy(eProfile, 0, newProfile, 0, 16);
            System.Buffer.BlockCopy(eRole, 0, newProfile, 16, eRole.Length);
            string originalProfile = Encoding.ASCII.GetString(ECB.Decrypt(Aes.Create(), eProfile, key, new byte[16], last:true));
            string adminProfile = Encoding.ASCII.GetString(ECB.Decrypt(Aes.Create(), newProfile, key, new byte[16], last:true));
            Console.WriteLine("Original Profile: " + originalProfile + "\nExpanded\n" + StringBaseConversion.KeyValueExtraction(originalProfile));
            Console.WriteLine("Admin Profile: " + adminProfile + "\nExpanded\n" + StringBaseConversion.KeyValueExtraction(adminProfile));
        }

        static void CBC_BitflipTest()
        {
            //; binary [00111011]
            //= binary [00111101]
            byte[] cipherText = CBC.CookieSandwichMaker("3admin5true3AAAA");
            byte[] original = CBC.Decrypt(cipherText, Utilities.g_key, new byte[16]);
            byte bitToFlip = 8; //00001000
            cipherText[16] ^= bitToFlip;
            cipherText[22] ^= bitToFlip;
            cipherText[27] ^= bitToFlip;
            byte[] plainText = CBC.Decrypt(cipherText, Utilities.g_key, new byte[16]);
            Console.WriteLine("Original text: " + Encoding.ASCII.GetString(original));
            if (FindAdminTrue(Encoding.ASCII.GetString(original)))
            {
                Console.WriteLine("ADMIN!");
            }
            else
            {
                Console.WriteLine("not admin.");
            }

            Console.WriteLine("Twiddled text: " + Encoding.ASCII.GetString(plainText));
            if (FindAdminTrue(Encoding.ASCII.GetString(plainText)))
            {
                Console.WriteLine("ADMIN!");
            }
            else
            {
                Console.WriteLine("not admin.");
            }

        }

        static byte[] CBC_PaddingOracleProcessCipherBlock(byte[] cipherBlock, byte [] iv, Dictionary<int, byte> solvedValues = null)
        {
            byte[] ivPrime = new byte[16];
            if (solvedValues == null)
            {
                solvedValues = new Dictionary<int, byte>(16);
            }
            for (int jj = 1 + solvedValues.Count; jj <= 16; /*Not used*/)
            {
                int pos = 16 - jj;
                System.Buffer.BlockCopy(iv, 0, ivPrime, 0, ivPrime.Length);
                ivPrime[ivPrime.Length - jj] ^= (byte)jj;
                for (int kk = 1; kk < jj; ++kk)
                {
                    ivPrime[ivPrime.Length - kk] ^= (byte)(jj ^ solvedValues[ivPrime.Length - kk]);
                }
                for (int kk = 0; kk < 256; ++kk)
                {
                    byte test = (byte)kk;
                    int offset = ivPrime.Length;
                    ivPrime[pos] ^= test;
                    bool valid = CBC.PaddingOracleDecrypt(cipherBlock, ivPrime);
                    if (valid)
                    {
                        solvedValues[pos] = test;
                        if (pos == 0)
                        {
                            List<byte> solution = new List<byte>(16);
                            for (int ii = 0; ii < 16; ++ii)
                            {
                                solution.Add(solvedValues[ii]);
                            }
                            return solution.ToArray();
                        }
                        var result = CBC_PaddingOracleProcessCipherBlock(cipherBlock, iv, solvedValues);
                        if (result != null)
                        {
                            return result;
                        }
                        else
                        {
                            solvedValues.Remove(pos);
                        }
                    }
                    ivPrime[pos] ^= test;
                }
                return null;
            }
            return null;
        }

        static void CBC_PaddingOracleAttack()
        {
            var temp = CBC.PaddingOracle();
            var cipherText = temp.Item1;
            var iv = temp.Item2;
            byte[] block = new byte[16];
            byte[] plaintext = new byte[0];
            for (int ii = 0; ii < cipherText.Length; ii += 16)
            {
                System.Buffer.BlockCopy(cipherText, ii, block, 0, block.Length);
                var plaintextBlock = CBC_PaddingOracleProcessCipherBlock(block, iv);
                plaintext = Utilities.Concatenate(plaintext, plaintextBlock);
                Console.WriteLine("Block #" + ii / 16 + ": " + Encoding.ASCII.GetString(plaintextBlock));
                System.Buffer.BlockCopy(block, 0, iv, 0, iv.Length);
            }
            Console.WriteLine("Full Plaintext: " + Encoding.ASCII.GetString(PKCS7Padding.Unpad(plaintext)));
        }

        static void CTRModeTest()
        {
            string base64Str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
            byte [] cipherText = Convert.FromBase64String(base64Str);
            CTR.Stream cstream = new CTR.Stream(Encoding.ASCII.GetBytes("YELLOW SUBMARINE"));
            byte [] block = new byte[16];
            byte[] nonce = new byte[8];
            for (int ii = 0; ii < cipherText.Length; ii += 16)
            {
                if (cipherText.Length - ii < block.Length)
                {
                    block = new byte[cipherText.Length - ii];
                }
                Buffer.BlockCopy(cipherText, ii, block, 0, block.Length);
                var plaintext = cstream.Decrypt(block, nonce);
                Console.Write(ASCIIEncoding.ASCII.GetString(plaintext));
            }
            Console.WriteLine(" . . . CTR Decrypt Complete");

        }

        static void CTRFixedNonceTest1()
        {
            StreamReader fin = new StreamReader(new FileStream("C:/Users/stephen.lavedas/dev/CryptoChallenge/TestFiles/CryptoChallenge19.txt", FileMode.Open));
            byte[] nonce = new byte[8];
            List<byte[]> streamCiphers = new List<byte[]>(40);
            int keylength = 0x7FFFFFFF;
            while (!fin.EndOfStream)
            {
                byte[] block = new byte[16];
                string line = fin.ReadLine();
                CTR.Stream cstream = new CTR.Stream(Utilities.GetGlobalKey());
                byte[] plainText = Convert.FromBase64String(line);
                if (plainText.Length < keylength)
                {
                    keylength = plainText.Length;
                }
                byte[] cipherText = new byte[plainText.Length];
                for (int ii = 0; ii < plainText.Length; ii += 16)
                {
                    if (plainText.Length - ii < block.Length)
                    {
                        block = new byte[plainText.Length - ii];
                    }
                    Buffer.BlockCopy(plainText, ii, block, 0, block.Length);
                    var cipherblock = cstream.Encrypt(block, nonce);
                    Buffer.BlockCopy(cipherblock, 0, cipherText, ii, cipherblock.Length);
                }
                streamCiphers.Add(cipherText);
            }
            fin.Close();

            byte [] keyCipherText = new byte[streamCiphers.Count * keylength];
            int ndx = 0;
            foreach (var item in streamCiphers)
            {
                Buffer.BlockCopy(item, 0, keyCipherText, ndx, keylength);
                ndx += keylength;
            }
            KeyTest.FindRepeatingKeyTest(keyCipherText, keylength);

        }

        static void RandomAccessCTRTest()
        {
            byte[] rawBytes = StringBaseConversion.Base64FileToByteArray("C:/Users/stephen.lavedas/dev/CryptoChallenge/TestFiles/Challenge25.txt");
            byte[] iv = new byte[16];
            byte[] key = ASCIIEncoding.ASCII.GetBytes("YELLOW SUBMARINE");
            Aes aesEngine = Aes.Create();
            var plaintextBytes = ECB.Decrypt(aesEngine, rawBytes, key, iv, last: true);
            CTR.Stream cstream = new CTR.Stream(null);
            byte [] cipherText = cstream.Encrypt(plaintextBytes, new byte[8]);
            byte [] cipherTextCopy = cipherText.Clone() as byte[];
            byte[] keystream = new byte[] { };
            byte[] newText = Encoding.ASCII.GetBytes("AAAAAAAAAAAAAAAA");
            for (int ii = 0; ii < cipherText.Length; ii += 16)
            {
                var length = Math.Min(cipherText.Length - ii, 16);
                if (length < newText.Length)
                {
                    newText = Encoding.ASCII.GetBytes(Encoding.ASCII.GetString(newText).Substring(newText.Length - length));
                }
                cstream.Edit(ref cipherText, (UInt64)ii, newText);
                byte[] newBlock = new byte[length];
                Buffer.BlockCopy(cipherText, ii, newBlock, 0, length);
                keystream = Utilities.Concatenate(keystream, ByteArrayXOR.FixedXOR(newBlock, newText));
            }
            var plainTextStr = Encoding.ASCII.GetString(ByteArrayXOR.FixedXOR(keystream, cipherTextCopy));
            Console.WriteLine("Recovered Plaintext: " + plainTextStr);
        }

        static void CTR_BitflipTest()
        {
            //; binary [00111011]
            //= binary [00111101]
            CTR.Stream estream = new CTR.Stream();
            CTR.Stream dstream = new CTR.Stream();

            byte[] cipherText = CTR.CookieSandwichMaker("3admin5true3AAAA", estream);
            byte[] original = dstream.Decrypt(cipherText, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
            dstream = new CTR.Stream();
            byte bitToFlip = 8; //00001000
            cipherText[32] ^= bitToFlip;
            cipherText[38] ^= bitToFlip;
            cipherText[43] ^= bitToFlip;
            byte[] plainText = dstream.Decrypt(cipherText, new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 });
            Console.WriteLine("Original text: " + Encoding.ASCII.GetString(original));
            if (FindAdminTrue(Encoding.ASCII.GetString(original)))
            {
                Console.WriteLine("ADMIN!");
            }
            else
            {
                Console.WriteLine("not admin.");
            }

            Console.WriteLine("Twiddled text: " + Encoding.ASCII.GetString(plainText));
            if (FindAdminTrue(Encoding.ASCII.GetString(plainText)))
            {
                Console.WriteLine("ADMIN!");
            }
            else
            {
                Console.WriteLine("not admin.");
            }

        }
        private static void CBC_IVisKeyText()
        {
            var key = Utilities.GenerateRandomKey();
            byte[] iv = new byte[key.Length];
            Buffer.BlockCopy(key, 0, iv, 0, iv.Length);
            var plainText = PKCS7Padding.Pad(Encoding.ASCII.GetBytes("This is the story, of a lovely lady, who was living with three very lovely girls!"), 16);
            var cipherText = CBC.Encrypt(plainText, key, iv);

            //Attacker
            byte[] newCipherText = new byte[48]; // three blocks
            Buffer.BlockCopy(cipherText, 0, newCipherText, 0, 16);
            Buffer.BlockCopy(cipherText, 0, newCipherText, 32, 16);

            // receiver
            var newPlainText = CBC.Decrypt(PKCS7Padding.Pad(newCipherText, key.Length), key, iv);
            // Check for high ascii
            bool valid = true;
            for (int ii = 0; valid && ii < newPlainText.Length; ++ii)
            {
                if (newPlainText[ii] > 127)
                {
                    valid = false;
                }
            }

            if (!valid) //Error was returned with messed up plaintext
            {
                byte[] p1 = new byte[16];
                byte[] p3 = new byte[16];
                Buffer.BlockCopy(newPlainText, 0, p1, 0, p1.Length);
                Buffer.BlockCopy(newPlainText, 32, p3, 0, p3.Length);
                var newKey = ByteArrayXOR.FixedXOR(p1, p3);
                bool match = true;
                for (int ii = 0; match && ii < newKey.Length; ++ii)
                {
                    Console.Write("{0:x2} ", newKey[ii]);
                    if (newKey[ii] != key[ii])
                    {
                        match = false;
                    }
                }
                if (match)
                {
                    Console.WriteLine(" . . . Keys MATCH");
                }
            }


        }

        static void Main(string[] args)
        {
            //AES_ECB_DecryptTest();
            //ECBDetectionTest();
            //var result = PKCS7Padding.Pad(ASCIIEncoding.ASCII.GetBytes("YELLOW SUBMARINE"), 20);
            //Console.WriteLine("Padded result to: " + ASCIIEncoding.ASCII.GetString(result));
            //AES_CBC_Test();
            //ECB_CBC_DetectionTest();
            //ECBSingleByteDecryptionTest();
            //ECB_CopyPasteTest();
            //ECBSingleByteDecryptionHardTest();
            //CBC_BitflipTest();
            //CBC_PaddingOracleAttack();
            //CTRModeTest();
            //CTRFixedNonceTest1();
            //RandomAccessCTRTest();
            //CTR_BitflipTest();

            CBC_IVisKeyText();
        }

    }
}
