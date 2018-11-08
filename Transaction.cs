using System;
using System.Text;
using BlockChainCourse.BlockWithMultipleTransactions.Interfaces;
using BlockChainCourse.Cryptography;

namespace BlockChainCourse.BlockWithMultipleTransactions
{
    public class Transaction : ITransaction
    {
        public string ID { get; set; }
        public string Name { get; set; }
        public bool Type { get; set; }
        public DateTime Timestamp { get; set; }
        public string Signature { get; set; }

        public Transaction(string id,
                            string name,
                            bool type,
                            DateTime timestamp)
        {
            ID = id;
            Name = name;
            Type = type;
            Timestamp = timestamp;
        }

        public void SetSignature(DigitalSignature rsa)
        {
            byte[] signData = rsa.SignData(CalculateTransactionHash());
            Signature = Convert.ToBase64String(signData);
        }

        public byte[] CalculateTransactionHash()
        {
            string txnHash = ID + Name + Type + Timestamp;
            return HashData.ComputeHashSha256(Encoding.UTF8.GetBytes(txnHash));
        }
    }
}