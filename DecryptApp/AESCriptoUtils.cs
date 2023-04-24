using Google.Apis.Auth.OAuth2;
using Google.Cloud.SecretManager.V1;
using System;
using System.IO;
using System.Security.Cryptography;

public class AESDecryptor
{
    // separador de linha UNIX pois o conteúdo da GCP vem com este separador diferente do ambiente Windows
    private static char NEWLINE_UNIX = '\n';

    // chaves de acesso a GCP do TCLOUD DEVOPS
    private static string TCLOUD_PROJECTID = "tcloud-devops";
    private static string TCLOUD_DEVOPS_AES_SECRETID = "tcloud-devops-AES-key";
    private static string TCLOUD_DEVOPS_IV_SECRETID = "tcloud-devops-Aes-IV";

    /// <summary>
    /// Instancia objetos da API da Google Cloud SDK, busca a KEY e o Algoritmo (IV) da chave AES pré-definida e utilizados na criptografia.
    /// Descriptografa e retorna string recebida.
    /// </summary>
    /// <param name="encrypted">texto a ser descriptografado</param>
    /// <returns>string descriptografada</returns>
    public static string Decrypt(string encrypted)
    {
        String result = null;

        using (Aes myAes = Aes.Create())
        {
            String contentKey = GetSecret(TCLOUD_PROJECTID, TCLOUD_DEVOPS_AES_SECRETID);
            String contentIV = GetSecret(TCLOUD_PROJECTID, TCLOUD_DEVOPS_IV_SECRETID);

            byte[] byteArrayKey = new byte[32];
            byteArrayKey = ConvertByteArray(byteArrayKey, contentKey);

            byte[] byteArrayIV = new byte[16];
            byteArrayIV = ConvertByteArray(byteArrayIV, contentIV);

            myAes.Key = byteArrayKey;
            myAes.IV = byteArrayIV;
            myAes.Mode = CipherMode.CBC;
            myAes.Padding = PaddingMode.PKCS7;

            byte[] encryptedBytes = Convert.FromBase64String(encrypted);

            ICryptoTransform decryptor = myAes.CreateDecryptor(myAes.Key, myAes.IV);

            using (MemoryStream msDecrypt = new MemoryStream(encryptedBytes))
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                    {
                        result = srDecrypt.ReadToEnd();
                    }
                }
            }

            return result;
        }
    }

    /// <sumary>
    /// Método que busca os secrets da GCP recebendo o secretId e projectId.
    /// </sumary>
    /// <param name="projectId">projectId da GCP</param>
    /// <param name="secretId">secretId da GCP</param>
    /// <param name="secretVersion">Valor fixo "latest" que pegará sempre a última versão da secret</param>
    /// <returns>chave descriptografada em string</returns>
    ///
    private static string GetSecret(string projectId, string secretId, string secretVersion = "latest")
    {
        Environment.SetEnvironmentVariable("GOOGLE_APPLICATION_CREDENTIALS", @"C:\toolsinstall\gcloud-bucket-secret.json");
        var client = SecretManagerServiceClient.Create();

        var secretName = new SecretName(projectId, secretId);
        var versionName = new SecretVersionName(projectId, secretId, secretVersion);

        // Acessa a versão do segredo especificado
        var secretVersionResponse = client.AccessSecretVersion(versionName);

        // Extrai o payload do segredo
        var payload = secretVersionResponse.Payload.Data.ToStringUtf8();

        return payload;
    }

    /// <summary>
    /// Converte o secret da GCP em byteArray para ser descriptografado
    /// </summary>
    /// <param name="byteArray">Array de bytes com tamanho pré definido para ser preenchido e retornado</param>
    /// <param name="secret">secret recebido da GCP</param>
    /// <returns>byteArray pronto para ser descriptografado</returns>
    private static byte[] ConvertByteArray(byte[] byteArray, string secret)
    {
        var arrayContentKey = secret.Split(NEWLINE_UNIX);

        if (byteArray.Length == arrayContentKey.Length)
        {
            for (int i = 0; i < byteArray.Length; i++)
            {
                byteArray[i] = Convert.ToByte(arrayContentKey[i]);
            }
        }

        return byteArray;
    }
}