using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.IO;
using System.Xml;
using System.Security.Cryptography;
using Microsoft.Win32;
using Newtonsoft.Json;

using BlockChainCourse.Cryptography;
using BlockChainCourse.BlockWithMultipleTransactions;
using BlockChainCourse.BlockWithMultipleTransactions.Interfaces;

namespace BlockWithMultipleTransactions
{
    public partial class Form4 : Form
    {
        int nBlock = 0;
        int MAX_TRANSACTION = 5;
        BlockChain chain = new BlockChain();
        IBlock cacheBlock = new Block(0);
        DigitalSignature rsa = new DigitalSignature();

        public Form4()
        {
            InitializeComponent();
            rsa.AssignNewKey();

            string subKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion";
            RegistryKey key = Microsoft.Win32.Registry.LocalMachine;
            RegistryKey skey = key.OpenSubKey(subKey);

            string name = skey.GetValue("ProductName").ToString();
            string releaseId = skey.GetValue("ReleaseId").ToString();
            lb_osInfo.Text = name + " " + releaseId + (Environment.Is64BitOperatingSystem ? " 64-bit" : " 32-bit");

            if (File.Exists("data.blc"))
            {
                chain.LoadFile("data.blc");

                for (int i = 0; i < chain.Blocks.Count; i++)
                {
                    nBlock++;
                    cb_blockList.Items.Add("Block " + (i + 1).ToString());
                }
                lb_blockName.Text = "Block " + (nBlock + 1).ToString();
                cb_blockList.SelectedIndex = cb_blockList.Items.Count - 1;
                cacheBlock = new Block(nBlock);
            }
        }

        private void switchTab(Bunifu.Framework.UI.BunifuTileButton button, Panel panel)
        {
            button.color = Color.FromArgb(66, 131, 222);
            panel.Visible = true;
            if (button.Name != "tbtn_cryption") {
                tbtn_cryption.color = Color.FromArgb(103, 103, 103);
                panel_encryption.Visible = false;
            }
            if (button.Name != "tbtn_blockchain") {
                tbtn_blockchain.color = Color.FromArgb(103, 103, 103);
                panel_blockchain.Visible = false;
            }
            if (button.Name != "tbtn_signFile")
            {
                tbtn_signFile.color = Color.FromArgb(103, 103, 103);
                panel_signFile.Visible = false;
            }
            if (button.Name != "tbtn_export")
            {
                tbtn_export.color = Color.FromArgb(103, 103, 103);
                panel_export.Visible = false;
            }
        }

        private void tbtn_cryption_Click(object sender, EventArgs e)
        {
            switchTab(tbtn_cryption, panel_encryption);
        }

        private void tbtn_signFile_Click(object sender, EventArgs e)
        {
            switchTab(tbtn_signFile, panel_signFile);
        }

        private void tbtn_blockchain_Click(object sender, EventArgs e)
        {
            switchTab(tbtn_blockchain, panel_blockchain);
        }

        private void tbtn_export_Click(object sender, EventArgs e)
        {
            switchTab(tbtn_export, panel_export);
        }

        private void btn_encrypt_Click(object sender, EventArgs e)
        {
            string plainText = tb_plainText.Text.Trim();
            if (plainText != "")
            {
                writeLog("Converting " + plainText + " to byte...");
                byte[] data = Encoding.UTF8.GetBytes(plainText);
                byte[] encrypted = rsa.Encrypt(data);
                writeLog("Using the public key to encrypt your text");
                tb_cipherText.Text = Convert.ToBase64String(encrypted);
                writeLog("-------------- The encryption is compeleted! --------------");
            }
            else
                AlertError("Nothing to encrypt.");
        }

        private void btn_signEncryption_Click(object sender, EventArgs e)
        {
            string plainText = tb_plainText.Text.Trim();
            if (plainText != "")
            {
                writeLog("Converting " + plainText + " to byte...");
                byte[] data = Encoding.UTF8.GetBytes(plainText);
                writeLog("Hashing data with SHA256...");
                byte[] sha256Hashed = HashData.ComputeHashSha256(data);
                tb_hash.Text = Convert.ToBase64String(sha256Hashed);
                writeLog("Complete hash your text.");

                writeLog("Using the private key to encrypt your text");
                byte[] signData = rsa.SignData(sha256Hashed);
                tb_signature.Text = Convert.ToBase64String(signData);
                writeLog("-------------- The signature is created! --------------");

            }
            else
                AlertError("Nothing to sign.");
        }

        private void btn_verifyEncryption_Click(object sender, EventArgs e)
        {
            if (tb_hash.Text != "" && tb_signature.Text != "")
            {
                try
                {
                    writeLog("Converting the hash and the signature to byte...");
                    byte[] sha256Hashed = Convert.FromBase64String(tb_hash.Text);
                    byte[] signature = Convert.FromBase64String(tb_signature.Text);

                    writeLog("Using the public key to verify");
                    writeLog("-------------- Complete --------------");
                    if (rsa.VerifySignature(sha256Hashed, signature))
                        AlertOK("Signature is verified");
                    else
                        AlertError("Signature not correct.");
                }
                catch (FormatException)
                {
                    AlertError("Hash or Signature not correct format.");
                }
            }
            else
                AlertError("Nothing to verify.");
                        
        }

        private void AlertError(string msg)
        {
            MessageBox.Show(msg,
                        "Error",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Error,
                        MessageBoxDefaultButton.Button1);
        }
        private void AlertOK(string msg)
        {
            MessageBox.Show(msg,
                        "Done!",
                        MessageBoxButtons.OK,
                        MessageBoxIcon.Information,
                        MessageBoxDefaultButton.Button1);
        }
        private void writeLog(string msg)
        {
            rtb_logs.Text += DateTime.Now.TimeOfDay + ": " + msg + Environment.NewLine;
        }

        private void btn_chooseFileToSign_Click(object sender, EventArgs e)
        {
            if (ofd_fileToSign.ShowDialog() == DialogResult.OK)
            {
                tb_fileToSign.text = ofd_fileToSign.FileName;

            }
            else
                tb_fileToSign.Text = string.Empty;
        }

        private void btn_chooseFileToSign_DragDrop(object sender, DragEventArgs e)
        {
            string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
            foreach (string file in files) Console.WriteLine(file);
        }

        private void btn_signFile_Click(object sender, EventArgs e)
        {
            string path = tb_fileToSign.text;
            if (path != "")
            {
                byte[] hash = SHA256.Create().ComputeHash(File.ReadAllBytes(path));

                var fileHash = new FileStream(path + "_hashed", FileMode.Create, FileAccess.Write);
                try
                {
                    fileHash.Write(hash, 0, hash.Length);
                }
                finally
                {
                    fileHash.Close();
                    fileHash.Dispose();
                }

                byte[] hashSigned = rsa.SignData(hash);
                var fs = new FileStream(path + "_signed", FileMode.Create, FileAccess.Write);
                try
                {
                    fs.Write(hashSigned, 0, hashSigned.Length);
                }
                finally
                {
                    fs.Close();
                    fs.Dispose();
                    AlertOK("File hash:" + path + "_hashed" + " is created" + Environment.NewLine
                        + "File signature:" + path + "_signed" + " is created");
                }
            }
            else AlertError("Nothing to sign.");
        }

        private void btn_verifyFile_Click(object sender, EventArgs e)
        {
            string path = tb_fileToSign.text;

            if (File.Exists(path + "_signed") && File.Exists(path + "_hashed"))
            {
                byte[] file = File.ReadAllBytes(path + "_signed");
                byte[] fileHash = File.ReadAllBytes(path + "_hashed");

                if (rsa.VerifySignature(fileHash, file))
                    AlertOK("Signature is verified.");
                else
                    AlertError("Signature not correct.");
            }
            else
                AlertError("Signature file && Hash file not found.");
        }

        private void btn_importPublicKey_Click(object sender, EventArgs e)
        {
            if (ofd_publicKey.ShowDialog() == DialogResult.OK)
            {
                lb_publicKey.Text = ofd_publicKey.SafeFileName;
                rsa.setPublicKey(File.ReadAllText(ofd_publicKey.FileName));
            }
            else
                lb_publicKey.Text = string.Empty;
        }

        private void btn_importPrivateKey_Click(object sender, EventArgs e)
        {
            if (ofd_privateKey.ShowDialog() == DialogResult.OK)
            {
                lb_privateKey.Text = ofd_privateKey.SafeFileName;
                rsa.setPrivateKey(File.ReadAllText(ofd_privateKey.FileName));
            }
            else
                lb_privateKey.Text = string.Empty;
        }

        private void btn_addTransactions_Click(object sender, EventArgs e)
        {
            string EmployerID = tb_id.Text.ToString().Trim();
            string Name = tb_name.Text.ToString().Trim();

            DateTime timestamp = DateTime.Now;

            if (EmployerID != "" && Name != "")
            {
                bool type = false;

                for (int i = 0; i < chain.Blocks.Count; i++)
                    for (int j = 0; j < chain.Blocks[i].Transaction.Count; j++)
                        if (chain.Blocks[i].Transaction[j].ID == EmployerID)
                            type = !chain.Blocks[i].Transaction[j].Type;

                for (int i = 0; i < cacheBlock.Transaction.Count; i++)
                    if (cacheBlock.Transaction[i].ID == EmployerID)
                        type = !cacheBlock.Transaction[i].Type;

                if (dgv_outTransactions.RowCount == 5) dgv_outTransactions.Rows.Clear();
                if (cacheBlock.Transaction.Count == 0)
                    cb_blockList.Items.Add("Block " + (nBlock + 1).ToString());

                ITransaction txn = new Transaction(EmployerID, Name, type, timestamp);
                txn.SetSignature(rsa);
                cacheBlock.AddTransaction(txn);

                if (cacheBlock.Transaction.Count == MAX_TRANSACTION)
                {
                    cacheBlock.SetBlockHash(nBlock == 0 ? null : chain.Blocks[nBlock - 1]);
                    chain.AcceptBlock(cacheBlock);
                    tb_previousBlockHash.Text = chain.Blocks[chain.Blocks.Count - 1].PreviousBlockHash != null 
                        ? chain.Blocks[chain.Blocks.Count - 1].PreviousBlockHash : "N/A";
                    lb_createdDate.Text = chain.Blocks[chain.Blocks.Count - 1].CreatedDate.ToString();
                    tb_blockHash.Text = chain.Blocks[chain.Blocks.Count - 1].BlockHash;
                    tb_merkleRoot.Text = chain.Blocks[chain.Blocks.Count - 1].getHashMerkleRoot();

                    nBlock += 1;
                    cacheBlock = new Block(nBlock);

                    lb_blockName.Text = "Block " + (nBlock + 1).ToString();
                }
                dgv_outTransactions.Rows.Add(EmployerID, Name, type ? "check-out" : "check-in", timestamp.ToString("HH:mm:ss"), timestamp.ToString("dd-MM-yyyy"), "unverified");

                cb_blockList.SelectedIndex = cb_blockList.Items.Count - 1;
                tb_name.Text = "";
                tb_id.Text = "";
                AlertOK(type ? "Checked-out!" : "Checked-in!");
            }
            else AlertError("Enter Employer ID and Name to add.");
        }

        private void btn_clear_Click(object sender, EventArgs e)
        {
            tb_name.Text = "";
            tb_id.Text = "";
        }

        private void blockchainTab_add_Click(object sender, EventArgs e)
        {
            blockchainTab_add.Normalcolor = Color.FromArgb(66, 131, 222);
            blockchainTab_manage.Normalcolor = Color.WhiteSmoke;

            blockchainTab_add.Textcolor = Color.White;
            blockchainTab_manage.Textcolor = Color.Black;

            blockchainPanel_manage.Visible = false;
            blockchainPanel_add.Visible = true; 
        }

        private void blockchainTab_manage_Click(object sender, EventArgs e)
        {
            blockchainTab_add.Normalcolor = Color.WhiteSmoke; 
            blockchainTab_manage.Normalcolor = Color.FromArgb(66, 131, 222);

            blockchainTab_add.Textcolor = Color.Black; 
            blockchainTab_manage.Textcolor = Color.White;

            blockchainPanel_add.Visible = false;
            blockchainPanel_manage.Visible = true;
        }

        private void cb_blockList_SelectedIndexChanged(object sender, EventArgs e)
        {
            int SelectedIndex = cb_blockList.SelectedIndex;
            List<ITransaction> transaction;
            if (cacheBlock.Transaction.Count != 0 && SelectedIndex == cb_blockList.Items.Count - 1)
            {
                transaction = cacheBlock.Transaction;
                tb_blockHash.Text = "N/A";
                tb_merkleRoot.Text = "N/A";
                tb_previousBlockHash.Text = chain.Blocks.Count != 0 ? chain.Blocks[chain.Blocks.Count-1].BlockHash : "N/A";
                lb_createdDate.Text = "N/A";
            }
            else
            {
                transaction = chain.Blocks[SelectedIndex].Transaction;
                tb_previousBlockHash.Text = chain.Blocks[SelectedIndex].PreviousBlockHash != null 
                    ? chain.Blocks[SelectedIndex].PreviousBlockHash : "N/A";

                tb_blockHash.Text = chain.Blocks[SelectedIndex].BlockHash;
                tb_merkleRoot.Text = chain.Blocks[SelectedIndex].getHashMerkleRoot();
                lb_createdDate.Text = chain.Blocks[SelectedIndex].CreatedDate.ToString();
            }
            
            dgv_outTransactions.Rows.Clear();
            for (int i = 0; i < transaction.Count; i++)
            {
                string EmployerID = transaction[i].ID;
                string Name = transaction[i].Name;
                bool type = transaction[i].Type;
                DateTime timestamp = transaction[i].Timestamp;
                dgv_outTransactions.Rows.Add(EmployerID, Name, type ? "check-out" : "check-in", timestamp.ToString("HH:mm:ss"), timestamp.ToString("dd-MM-yyyy"), "unverified");
            }
        }

        private void btn_verifyBlockchain_Click(object sender, EventArgs e)
        {
            if (chain.Blocks.Count > 0)
                if (chain.VerifyChain())
                    AlertOK("Blockchain integrity intact.");
                else
                    AlertOK("Blockchain integrity NOT intact.");
            else
                AlertError("Genesis block not set.");
        }

        private void btn_verifyTransactions_Click(object sender, EventArgs e)
        {
            int SelectedIndex = cb_blockList.SelectedIndex;
            List<ITransaction> transaction;
            if (chain.Blocks.Count > 0 || cacheBlock.Transaction.Count > 0)
            {
                if (cacheBlock.Transaction.Count != 0 && SelectedIndex == cb_blockList.Items.Count - 1)
                    transaction = cacheBlock.Transaction;
                else
                    transaction = chain.Blocks[SelectedIndex].Transaction;


                for (int i = 0; i < transaction.Count; i++)
                {
                    byte[] hash = transaction[i].CalculateTransactionHash();
                    byte[] signature = Convert.FromBase64String(transaction[i].Signature);
                    if (rsa.VerifySignature(hash, signature))
                        dgv_outTransactions.Rows[i].Cells[5].Value = "verified";
                    else
                        dgv_outTransactions.Rows[i].Cells[5].Value = "wrong";
                }
            }
            else
                AlertError("Nothing to verify");
        }

        private void btn_exportBlockchain_Click(object sender, EventArgs e)
        {
            TextWriter writer = null;
            try
            {
                var contentsToWriteToFile = JsonConvert.SerializeObject(chain);
                writer = new StreamWriter("data.blc", false);
                writer.Write(contentsToWriteToFile);
            }
            finally
            {
                if (writer != null)
                {
                    writer.Close();
                    AlertOK("Exported your blockchain.");
                }
            }
        }

        private void btn_exportPublicKey_Click(object sender, EventArgs e)
        {
            if (sfd_publicKey.ShowDialog() == DialogResult.OK)
            {
                StreamWriter publicKeyWriter = null;
                String xmlPublicKey = rsa.getPublicKey();
                publicKeyWriter = new StreamWriter(sfd_publicKey.FileName);
                publicKeyWriter.Write(xmlPublicKey);
                publicKeyWriter.Close();
                publicKeyWriter.Dispose();
                AlertOK("Exported the public key.");
            }
        }

        private void btn_exportPrivateKey_Click(object sender, EventArgs e)
        {
            if (sfd_privateKey.ShowDialog() == DialogResult.OK)
            {
                StreamWriter privateKeyWriter = null;
                String xmlPrivateKey = rsa.getPrivateKey();
                privateKeyWriter = new StreamWriter(sfd_privateKey.FileName);
                privateKeyWriter.Write(xmlPrivateKey);
                privateKeyWriter.Close();
                privateKeyWriter.Dispose();
                AlertOK("Exported the private key.");
            }
        }
    }
}
