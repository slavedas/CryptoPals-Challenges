using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace CryptoChallenge
{
    public class StringBaseConversion
    {
        public static string KeyValueExtraction(string cookie)
        {
            string result = "{";
            while (cookie != "")
            {
                var valueStart = cookie.IndexOf('=');
                var valueEnd = cookie.IndexOf('&');
                var key = cookie.Substring(0, valueStart);
                int valLength = 0;
                if (valueEnd != -1)
                {
                    valLength = valueEnd - (valueStart + 1);
                }
                else
                {
                    valLength = cookie.Length - (valueStart + 1);
                }
                var value = cookie.Substring(valueStart + 1, valLength);
                result += "\n  " + key + ": \'" + value + "\'";
                if (valueEnd == -1)
                {
                    cookie = "";
                }
                else
                {
                    cookie = cookie.Substring(valueEnd + 1);
                    if (cookie.Length != 0)
                    {
                        result += ",";
                    }
                }

            }
            result += "\n}";
            return result;
        }

        public static string profile_for(string email)
        {
            while ((email.IndexOf('=')) >= 0)
            {
                email = email.Remove(email.IndexOf('='),1);
            }
            while ((email.IndexOf('&')) >= 0)
            {
                email = email.Remove(email.IndexOf('&'),1);
            }
            return "email=" + email + "&uid=10&role=user";
        }

        public static byte[] HexStringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length / 2).Select(x => Convert.ToByte(hex.Substring(x * 2, 2), 16)).ToArray();
        }

        public static byte[] Base64FileToByteArray(string filename)
        {
            System.IO.StreamReader sr = new System.IO.StreamReader(filename);
            char[] base64Text = new char[sr.BaseStream.Length];
            sr.Read(base64Text, 0, (int)sr.BaseStream.Length);
            sr.Close();
            return Convert.FromBase64CharArray(base64Text, 0, base64Text.Length);
        }
        public static List<byte[]> Base64FileToByteArrayByLine(string filename)
        {
            System.IO.StreamReader sr = new System.IO.StreamReader(filename);
            List<byte[]> result = new List<byte[]>();
            while (!sr.EndOfStream)
            {
                string line = sr.ReadLine();
                result.Add(Convert.FromBase64String(line));
            }
            sr.Close();
            return result;
        }
        static void Main(string[] args)
        {

            string hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
            var rawByteData = HexStringToByteArray(hex);
            string base64 = System.Convert.ToBase64String(rawByteData);
            Console.WriteLine("Hex: " + hex + "\nBase 64: " + base64);
            string profile = profile_for("test@gmail.com&role=admin");
            string expanded = KeyValueExtraction(profile);
            Console.WriteLine("Create profile: " + profile + "\nKey value extraction:\n" + expanded);
        }
    }
}
