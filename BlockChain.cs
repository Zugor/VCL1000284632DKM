using System;
using System.IO;
using Newtonsoft.Json;
using System.Collections.Generic;
using BlockChainCourse.BlockWithMultipleTransactions.Interfaces;

namespace BlockChainCourse.BlockWithMultipleTransactions
{
    public class BlockChain : IBlockChain
    {
        public IBlock CurrentBlock { get; private set; }
        public IBlock HeadBlock { get; private set; }

        public List<IBlock> Blocks { get; }

        public BlockChain()
        {
            Blocks = new List<IBlock>();
        }

        public void LoadFile(string path)
        {
            TextReader reader = null;
            try
            {
                reader = new StreamReader(path);
                var fileContents = reader.ReadToEnd();
                dynamic chain = JsonConvert.DeserializeObject(fileContents);

                for (int i = 0; i < chain.Blocks.Count; i++)
                {
                    IBlock block = new Block(i);
                    for (int j = 0; j < chain.Blocks[i].Transaction.Count; j++)
                    {
                        dynamic transaction = chain.Blocks[i].Transaction[j];
                        string ID = transaction.ID;
                        string Name = transaction.Name;
                        bool Type = transaction.Type;
                        DateTime Timestamp = transaction.Timestamp;
                        string signature = transaction.Signature;     
                        
                        ITransaction txn = new Transaction(ID, Name, Type, Timestamp);
                        txn.Signature = signature;
                        block.AddTransaction(txn);
                    }
                    AcceptBlock(block);
                }
                for (int i = 0; i < Blocks.Count; i++)
                    Blocks[i].SetBlockHash(i == 0 ? null : Blocks[i-1]);
                
            }
            finally
            {
                if (reader != null)
                    reader.Close();
            } 
        }

        public void AcceptBlock(IBlock block)
        {
            // This is the first block, so make it the genesis block.
            if (HeadBlock == null)
            {
                HeadBlock = block;
                HeadBlock.PreviousBlockHash = null;
            }

            CurrentBlock = block;
            Blocks.Add(block);
        }

        public int NextBlockNumber
        {
            get
            {
                if (HeadBlock == null)
                { 
                    return 0; 
                }

                return CurrentBlock.BlockNumber + 1;
            }
        }

        public bool VerifyChain()
        {
            if (HeadBlock == null)
                return false;

            bool isValid = HeadBlock.IsValidChain(null, true);

            if (isValid)
                return true;  
            else
                return false;
            
        }
    }
}
