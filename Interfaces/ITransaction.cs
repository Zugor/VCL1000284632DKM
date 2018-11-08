using System;
using BlockChainCourse.Cryptography;

namespace BlockChainCourse.BlockWithMultipleTransactions.Interfaces
{
    public interface ITransaction
    {
        string ID { get; set; }
        string Name { get; set; }
        bool Type { get; set; }
        DateTime Timestamp { get; set; }
        string Signature { get; set; }

        byte[] CalculateTransactionHash();
        void SetSignature(DigitalSignature rsa);
    }
}
