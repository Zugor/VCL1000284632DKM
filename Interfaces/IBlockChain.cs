namespace BlockChainCourse.BlockWithMultipleTransactions.Interfaces
{
    public interface IBlockChain
    {
        void AcceptBlock(IBlock block);
        int NextBlockNumber { get; }
        bool VerifyChain();
    }
}
