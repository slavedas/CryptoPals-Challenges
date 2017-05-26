using System;
using System.Collections.Generic;
using System.Linq;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using CryptoChallenge;

namespace XORFunctions
{
    public class ByteArrayXOR
    {

        public static Boolean m_PrintDebug = false;
        public static string m_debugString = "";
        public static byte[] FixedXOR(byte[] buf1, byte[] buf2)
        {
            if (buf1.Length != buf2.Length)
            {
                throw new ArgumentException("Fixed XOR Buffers must have equal lengths");
            }
            byte[] result = new byte[buf1.Length];
            for (int ii = 0; ii < buf1.Length; ++ii)
            {
                result[ii] = (byte)(buf1[ii] ^ buf2[ii]);
            }
            return result;
        }

        public static byte[] RepeatedXOR(byte[] key, byte[] msg)
        {
            byte[] result = new byte[msg.Length];
            for (int ii = 0; ii < msg.Length; ++ii)
            {
                result[ii] = (byte)(key[ii % key.Length] ^ msg[ii]);
            }
            return result;
        }

        static void FixedXORTest()
        {
            var hexString = "1c0111001f010100061a024b53535009181c";
            var rawBytes = StringBaseConversion.HexStringToByteArray(hexString);

            var xorString = "686974207468652062756c6c277320657965";
            var rawXorBytes = StringBaseConversion.HexStringToByteArray(xorString);

            var xordBytes = FixedXOR(rawBytes, rawXorBytes);
            string hexResult = BitConverter.ToString(xordBytes).Replace("-", "");
            Console.WriteLine("Fixed XOR Result: " + hexResult);
        }

        public static int ScorePlainText(byte[] text)
        {
            var histogram = PlainTextHistogram(text);
            var histSum = HistogramSum(histogram);
            if (histSum == 0)
            {
                return 0;
            }
            var lowerCount = CountBetweenValues(histogram, (byte)'a', (byte)'z');
            var upperCount = CountBetweenValues(histogram, (byte)'A', (byte)'Z');
            double countRatio = (double)lowerCount / upperCount;
            var maxPair = MaxHistogramValue(histogram, new byte[1] { (byte)' ' });
            int score = histogram[(byte)' '] + lowerCount;//(int)((double)histSum / text.Length * (countRatio * (histogram[(byte)' '] * maxPair.Value)));
            if (m_PrintDebug)
            {
                Console.WriteLine(m_debugString + " histSum: " + histSum + " textLength: " + text.Length + " maxPair: " + maxPair.ToString() + " numSpaces: " + histogram[(byte)' '] + " upperCount: " + upperCount + " lowerCount: " + lowerCount + " score: " + score);
            }
            return score;
        }

        public static Tuple<byte, int, byte[]> FindBestSingleXORKey(byte[] rawBytes)
        {
            var xorResults = new Dictionary<byte, byte[]>();
            for (byte key = 1; key != 0; ++key)
            {
                var keyByte = new byte[1];
                keyByte[0] = key;
                xorResults[key] = RepeatedXOR(keyByte, rawBytes);
                string result = ASCIIEncoding.ASCII.GetString(xorResults[key]);
            }

            var scores = new Dictionary<byte, int>();
            byte highScoreKey = 1;

            foreach (var result in xorResults)
            {
                var key = result.Key;
                var bytes = result.Value;
                if (m_PrintDebug)
                {
                    m_debugString = "For Key: " + key.ToString();
                }
                int score = ScorePlainText(bytes);
                scores[key] = score;
                if (score > scores[highScoreKey])
                {
                    highScoreKey = key;
                }
            }
            return new Tuple<byte, int, byte[]>(highScoreKey, scores[highScoreKey], xorResults[highScoreKey]);
        }

        public static void RepeatingXORFileEncryption(string plaintextKey, System.IO.BinaryReader infile, System.IO.BinaryWriter outfile)
        {
            if (infile == null || outfile == null)
            {
                throw new ArgumentNullException("file", "File is null");
            }
            byte[] keyBytes = ASCIIEncoding.ASCII.GetBytes(plaintextKey);
            int readSize = keyBytes.Length * 100;
            byte[] readBuffer = new byte[readSize];
            while (infile.BaseStream.Position < infile.BaseStream.Length)
            {
                var count = infile.Read(readBuffer, 0, readSize);
                if (count > 0)
                {
                    //We'll xor past the end for the final read, but only write the correct amount
                    var xorBytes = RepeatedXOR(keyBytes, readBuffer);
                    outfile.Write(xorBytes, 0, count);
                }
            }
        }

        static Dictionary<byte, int> PlainTextHistogram(byte[] text)
        {
            //32 65-90 97-122
            var bins = new Dictionary<byte, int>();
            bins[13] = 0;
            bins[10] = 0;
            for (byte ii = 32; ii <= 126; ++ii)
            {
                bins[ii] = 0;
            }
            foreach (byte b in text)
            {
                if (bins.ContainsKey(b))
                {
                    bins[b] += 1;
                }
            }
            return bins;
        }

        static int HistogramSum(Dictionary<byte, int> hist)
        {
            int result = 0;
            foreach (var value in hist)
            {
                result += value.Value;
            }

            return result;
        }

        static int CountBetweenValues(Dictionary<byte, int> hist, byte lowValue, byte highValue)
        {
            int count = 0;
            for (byte ii = lowValue; ii <= highValue; ++ii)
            {
                count += hist[ii];
            }
            return count;
        }
        static KeyValuePair<byte, int> MaxHistogramValue(Dictionary<byte, int> hist, byte[] exclusions=null)
        {
            KeyValuePair<byte, int> maxVal = new KeyValuePair<byte,int>(0,0);
            foreach (var value in hist)
            {
                if (exclusions != null && exclusions.Contains(value.Key))
                {
                    continue;
                }
                if (maxVal.Value < value.Value)
                {
                    maxVal = value;
                }
            }
            return maxVal;
        }

        static void SingleByteXORTest()
        {
            var hexString = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
            var rawBytes = StringBaseConversion.HexStringToByteArray(hexString);
            Console.WriteLine("Raw Bytes: " + ASCIIEncoding.ASCII.GetString(rawBytes));
            var result = FindBestSingleXORKey(rawBytes);
            Console.WriteLine("XOR Key = " + result.Item2 + " Text: " + ASCIIEncoding.ASCII.GetString(result.Item3));            
        }

        static void FindSingleByteXORTest()
        {
            var fin = new System.IO.StreamReader("C:/Users/stephen.lavedas/Downloads/FindXORKeyString.txt");
            if (fin == null)
            {
                throw new ArgumentNullException("Unable to open file for reading!");
            }
            int count = 0;
            var resultsByLine = new Dictionary<int, Tuple<byte, int, byte[]> >();
            while (!fin.EndOfStream)
            {
                var line = fin.ReadLine();
                var rawBytes = StringBaseConversion.HexStringToByteArray(line);
                Console.WriteLine("**** Line #" + count + " ****");
                if (count == 170)
                {
                    m_PrintDebug = true;
                }
                else { m_PrintDebug = false; }
                var result = FindBestSingleXORKey(rawBytes);
                resultsByLine[count] = result;
                //Console.WriteLine("Line #" + count.ToString() + " XOR Key = " + result.Item1 + " Text: " + ASCIIEncoding.ASCII.GetString(result.Item3));
                ++count;
            }

            int maxScoreLine = 0;
            foreach (var pair in resultsByLine)
            {
                if (pair.Value.Item2 > resultsByLine[maxScoreLine].Item2)
                {
                    maxScoreLine = pair.Key;
                }
            }
            var bestResult = resultsByLine[maxScoreLine];
            Console.WriteLine("Best Choice is Line #" + maxScoreLine.ToString() + " XOR Key = " + bestResult.Item1 + " Text: " + ASCIIEncoding.ASCII.GetString(bestResult.Item3));
        }

        static void RepeatingKeyXORTest()
        {
            string asciiString = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
            byte[] rawBytes = ASCIIEncoding.ASCII.GetBytes(asciiString);
            string keyString = "ICE";
            byte[] keyBytes = ASCIIEncoding.ASCII.GetBytes(keyString);
            var encryptedText = RepeatedXOR(keyBytes, rawBytes);
            string hexResult = BitConverter.ToString(encryptedText).Replace("-", "");
            string expectedResult = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
            expectedResult = expectedResult.ToUpper();
            Console.WriteLine("Repeating Key Result: " + hexResult + " This " + ((hexResult == expectedResult) ? "Matches":"Does NOT Match") + " the expected result");
        }

        static void FileXORTest()
        {
            System.IO.FileStream ifs = new System.IO.FileStream("C:/Users/stephen.lavedas/Downloads/CyberChef.htm.xor", System.IO.FileMode.Open);
            System.IO.FileStream ofs = new System.IO.FileStream("C:/Users/stephen.lavedas/Downloads/CyberChef2.htm", System.IO.FileMode.OpenOrCreate);
            var infile = new System.IO.BinaryReader(ifs);
            var outfile = new System.IO.BinaryWriter(ofs);
            RepeatingXORFileEncryption("Sparrow", infile, outfile);
        }

        static void Main(string[] args)
        {
            FixedXORTest();
            SingleByteXORTest();
            try
            {
                FindSingleByteXORTest();
            } catch (ArgumentNullException exp)
            {
                Console.WriteLine(exp.Message);
            }
            RepeatingKeyXORTest();
            FileXORTest();
        }
    }
}
