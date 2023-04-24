using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace DecryptApp
{
    class Program
    {
        public static void Main()
        {
            try { 
                Console.WriteLine(AESDecryptor.Decrypt(@"SrjzSCUMOc6vYlt3nnxxa6dkQpX8WXUgvpIkNv4NZVk="));
            } catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
