using System;
using System.Linq;
using System.Text;
using System.Windows;
using Microsoft.Win32;
using System.IO;
using System.Diagnostics;

using System.Numerics;
using System.Collections.Generic;
using System.Security.Cryptography; //for more cryptographic exceptions

namespace KryptologieLAB_03
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        /// <summary>
        /// AES mode of operation
        /// </summary>
        private enum OperationMode
        {
            /// <summary>
            /// Electronic Code Book: each block of the plaintext is enciphered separately
            /// </summary>
            ECB,

            /// <summary>
            /// Cipher Block Chaining: each block of the plaintext is XORed with the previous ciphertext block before being enciphered. The first plaintext block is XORed with an initialisation vector.
            /// </summary>
            CBC,

            /// <summary>
            /// Output Feedback: an initialisation vector is repeatedly enciphered and each block of the plaintext is XORed with the corresponding enciphered initialisation vector.
            /// </summary>
            OFB,

            /// <summary>
            /// Cipher Feedback: each block of plaintext is enciphered by XORing it with the previous ciphertext block that has been enciphered a second time. The first plaintext block is XORed with an enciphered initialisation vector.
            /// </summary>
            CFB
        }



        #region UI events + extraction of variables from the UI
        private void cbOperationMode_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
        {
            //show/hide input boxes as needed by the mode of operation
            switch (GetOperationMode())
            {
                case OperationMode.ECB:
                    lbOperationBlockBitCount.Visibility = Visibility.Hidden;
                    cbOperationBlockBitCount.Visibility = Visibility.Hidden;
                    lbInitialisationVector.Visibility = Visibility.Hidden;
                    tbInitialisationVector.Visibility = Visibility.Hidden;
                    break;

                case OperationMode.CBC:
                    lbOperationBlockBitCount.Visibility = Visibility.Hidden;
                    cbOperationBlockBitCount.Visibility = Visibility.Hidden;
                    lbInitialisationVector.Visibility = Visibility.Visible;
                    tbInitialisationVector.Visibility = Visibility.Visible;
                    break;

                case OperationMode.OFB:
                    lbOperationBlockBitCount.Visibility = Visibility.Visible;
                    cbOperationBlockBitCount.Visibility = Visibility.Visible;
                    lbInitialisationVector.Visibility = Visibility.Visible;
                    tbInitialisationVector.Visibility = Visibility.Visible;
                    break;

                case OperationMode.CFB:
                    lbOperationBlockBitCount.Visibility = Visibility.Visible;
                    cbOperationBlockBitCount.Visibility = Visibility.Visible;
                    lbInitialisationVector.Visibility = Visibility.Visible;
                    tbInitialisationVector.Visibility = Visibility.Visible;
                    break;

                default:
                    //invalid item -> switch to ECB
                    cbOperationMode.SelectedIndex = 0;
                    break;
            }
        }
        
        /// <summary>
        /// Determines the currently selected mode of operation in the UI
        /// </summary>
        /// <returns>Current mode of operation. Returns null of an invalid value is selected.</returns>
        private OperationMode? GetOperationMode()
        {
            switch (cbOperationMode.SelectedIndex)
            {
                case 0:
                    return OperationMode.ECB;

                case 1:
                    return OperationMode.CBC;

                case 2:
                    return OperationMode.OFB;

                case 3:
                    return OperationMode.CFB;

                default:
                    return null;
            }
        }

        /// <summary>
        /// Ensures that all inputs in the window that are required for encrypting/decrypting are set and valid. If any input is missing or invalid, a MessageBox is displayed.
        /// </summary>
        /// <param name="inputIsHexBytes">Ensure that the input consists of hexadecimal bytes separated by spaces. This is required for how I've implemented the deciphering process.</param>
        /// <returns>Boolean indicating whether all inputs are valid</returns>
        private bool CheckInputsAreValid(bool inputIsHexBytes = false)
        {
            //check operation mode
            bool isOperationBlockBitCountRequired = false;
            bool isInitialisationVectorRequired = false;
            switch (GetOperationMode())
            {
                case OperationMode.ECB:
                    break;

                case OperationMode.CBC:
                    isInitialisationVectorRequired = true;
                    break;

                case OperationMode.OFB:
                    isOperationBlockBitCountRequired = true;
                    isInitialisationVectorRequired = true;
                    break;

                case OperationMode.CFB:
                    isOperationBlockBitCountRequired = true;
                    isInitialisationVectorRequired = true;
                    break;

                default:
                    MessageBox.Show("Please select one of the given operation modes.", "Invalid operation mode detected.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                    return false;
            }

            //check for empty textboxes and invalid comboboxes
            if (tbInput.Text == "")
            {
                MessageBox.Show("Please enter a text.", "No input detected.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                return false;
            }
            if (tbKey.Text == "")
            {
                MessageBox.Show("Please enter a key (hex 32-bit integers according to the AES bit count).", "No key detected.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                return false;
            }
            if (isOperationBlockBitCountRequired)
            {
                switch (cbOperationBlockBitCount.Text)
                {
                    case "128 Bit":
                        break;

                    default:
                        MessageBox.Show("Please select one of the given operation block bit counts.", "Invalid operation block bit count detected.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                        return false;
                }
            }
            if (isInitialisationVectorRequired)
            {
                if (tbInitialisationVector.Text == "")
                {
                    if (cbOperationMode.Text == "CBC")
                        MessageBox.Show("Please enter an initialisation vector (hex 32-bit integers according to the AES bit count).", "Invalid initialisation vector detected.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                    else
                        MessageBox.Show("Please enter an initialisation vector (hex 32-bit integers according to the operation block bit count).", "Invalid initialisation vector detected.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                    return false;
                }
            }

            //check hex input if required
            if (inputIsHexBytes)
            {
                try
                {
                    byte[] input = tbInput.Text.Trim().Split(" ").Select((string byteStr) => Convert.ToByte(byteStr, 16)).ToArray(); //Trim() removes leading and trailing whitespace characters
                }
                catch (Exception)
                {
                    MessageBox.Show("The input needs to consist of hexadecimal bytes separated by spaces.", "Invalid input detected.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                    return false;
                }
            }

            //check key
            try
            {
                GetKey();
            }
            catch (Exception)
            {
                MessageBox.Show("The key must consist of hex 32-bit integers according to the AES bit count separated by spaces.", "Key is not an integer array.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                return false;
            }

            //check initialisation vector (if necessary)
            if (isInitialisationVectorRequired)
            {
                try
                {
                    GetInitVector();
                }
                catch (Exception)
                {
                    if (cbOperationMode.Text == "CBC")
                        MessageBox.Show("The initialisation vector must consist of hex byte values according to the AES bit count separated by spaces.", "Initialisation vector is not a byte array.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                    else
                        MessageBox.Show("The initialisation vector must consist of hex byte values according to the operation block bit count separated by spaces.", "Initialisation vector is not a byte array.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                    return false;
                }
            }

            //no missing/invalid inputs detected
            return true;
        }
        
        /// <summary>
        /// Determines the key given in the UI
        /// </summary>
        /// <returns>Key given in the UI</returns>
        private int[] GetKey()
        {
            string[] separatedKeys;
            int[] key;
            separatedKeys = tbKey.Text.Trim().Split(" "); //Trim() removes leading and trailing whitespace characters
            key = separatedKeys.Select<string, int>((string separatedKey) => Convert.ToInt32(separatedKey, 16)).ToArray();
            //for 128 bit keys, there will be 4 = 128/32 entries in key[]

            return key;
        }

        /// <summary>
        /// Determines the initialisation vector given in the UI
        /// </summary>
        /// <returns>Initialisation vector given in the UI</returns>
        private byte[] GetInitVector()
        {
            string[] separatedInitVector;
            byte[] initVector;
            separatedInitVector = tbInitialisationVector.Text.Trim().Split(" "); //Trim() removes leading and trailing whitespace characters
            initVector = separatedInitVector.Select<string, byte>((string initVectorPart) => Convert.ToByte(initVectorPart, 16)).ToArray();

            return initVector;
        }
        #endregion



        #region Encipher/decipher with key
        private void cmdEncipherKey_Click(object sender, RoutedEventArgs e)
        {
            if (!CheckInputsAreValid())
            {
                return;
            }

            int[] key = GetKey();

            byte[] input = Encoding.UTF8.GetBytes(tbInput.Text);
            byte[] cipherText;

            switch (GetOperationMode())
            {
                case OperationMode.ECB:
                    cipherText = GetCiphertext_AES(input, key, OperationMode.ECB, 16);
                    break;

                case OperationMode.CBC:
                    cipherText = GetCiphertext_AES(input, key, OperationMode.CBC, 16, initialisationVector: GetInitVector());
                    break;

                case OperationMode.OFB:
                    cipherText = GetCiphertext_AES(input, key, OperationMode.OFB, 16, operationBlockBitCount: 128, initialisationVector: GetInitVector());
                    break;

                case OperationMode.CFB:
                    cipherText = GetCiphertext_AES(input, key, OperationMode.CFB, 16, operationBlockBitCount: 128, initialisationVector: GetInitVector());
                    break;

                default:
                    return; //shouldn't occur - already checked in CheckInputsAreValid (it's just that the default clause is obligatory)
            }

            string outputText = "";
            for (int i = 0; i < cipherText.Length - 1; ++i)
            {
                outputText += Convert.ToString(cipherText[i], 16) + " "; //output the array as hexadecimal bytes separated by spaces -> more straightforward than using strings
            }
            outputText += Convert.ToString(cipherText[cipherText.Length - 1], 16);
            tbOutput.Text = outputText;

            MessageBox.Show("The text has been enciphered.", "Text has been enciphered.", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void cmdDecypherKey_Click(object sender, RoutedEventArgs e)
        {
            if (!CheckInputsAreValid(inputIsHexBytes: true))
            {
                return;
            }

            int[] key = GetKey();

            byte[] input = tbInput.Text.Trim().Split(" ").Select((string byteStr) => Convert.ToByte(byteStr, 16)).ToArray(); //Trim() removes leading and trailing whitespace characters
            byte[] plainText;

            switch (GetOperationMode())
            {
                case OperationMode.ECB:
                    plainText = GetPlaintext_AES(input, key, OperationMode.ECB, 16);
                    break;

                case OperationMode.CBC:
                    plainText = GetPlaintext_AES(input, key, OperationMode.CBC, 16, initialisationVector: GetInitVector());
                    break;

                case OperationMode.OFB:
                    plainText = GetPlaintext_AES(input, key, OperationMode.OFB, 16, operationBlockBitCount: 128, initialisationVector: GetInitVector());
                    break;

                case OperationMode.CFB:
                    plainText = GetPlaintext_AES(input, key, OperationMode.CFB, 16, operationBlockBitCount: 128, initialisationVector: GetInitVector());
                    break;

                default:
                    return; //shouldn't occur - already checked in CheckInputsAreValid (it's just that the default clause is obligatory)
            }

            string outputText = Encoding.UTF8.GetString(plainText);
            tbOutput.Text = outputText;

            MessageBox.Show("The text has been deciphered.", "Text has been deciphered.", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        /// <summary>
        /// Calculates the ciphertext of the given input using the Advanced Encryption Standard.
        /// </summary>
        /// <param name="input">The input (e.g. a text) that has been converted to an array of bytes</param>
        /// <param name="key">The key with which to encipher the input. It's length needs to be the same as byteCount.</param>
        /// <param name="mode">The mode of operation with which to encipher the input</param>
        /// <param name="byteCount">The block length used to encipher the input. Only 16 byte (128 bit) are supported at the moment.</param>
        /// <param name="operationBlockBitCount">Some modes of operation require a block length lower than or equal to byteCount during calculations. Again, only 128 bit are supported at the moment.</param>
        /// <param name="initialisationVector">Some modes of operation require an initialisation vector. The vector's length is either the same as byteCount or as operationBlockBitCount depending on the mode of operation.</param>
        /// <returns>Input enciphered with the given key</returns>
        private byte[] GetCiphertext_AES(byte[] input, int[] key, OperationMode mode, int byteCount, int operationBlockBitCount = 128, byte[] initialisationVector = null)
        {
            if (key.Length != 4)
            {
                throw new NotSupportedException("Only 128-bit keys are currently supported.");
            }

            byte[] output;
            if (input.Length % byteCount != 0) //ensure that input.Length is a multiple of byteCount!
            {
                Trace.WriteLine($"Applying padding ({input.Length} to {(int)Math.Ceiling((float)input.Length / byteCount) * byteCount} byte)...");
                output = new byte[(int)Math.Ceiling((float)input.Length / byteCount) * byteCount]; //pad to next multiple of byteCount
                Array.Copy(input, 0, output, 0, input.Length); //copy input to empty output. rest will be 0 (padding)
            }
            else
            {
                output = new byte[input.Length];
                Array.Copy(input, 0, output, 0, input.Length); //copy input to empty output. no padding required
            }

            AESInputView view = AESInputView.FromMode(output, 16, mode, operationBlockBitCount = 128); //automatically builds square block views. For functionality, see summary at the AESInputView class
            byte[] SBox = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
            byte[][] K = GetRoundKeys(key, 11, SBox); //11 round keys

            switch (mode)
            {
                case OperationMode.ECB:
                    for (int blockIndex = 0; blockIndex < view.SquareBlockCount; ++blockIndex)
                    {
                        EncipherBlock_ECB(view.squareBlockViews[blockIndex], K, SBox);
                    }
                    break;

                case OperationMode.CBC:
                    byte[] initVectorCBC = initialisationVector;
                    EncipherBlock_CBC(view.squareBlockViews[0], initVectorCBC, null, K, SBox); //no previous block during the first encryption
                    for (int blockIndex = 1; blockIndex < view.SquareBlockCount; ++blockIndex)
                    {
                        EncipherBlock_CBC(view.squareBlockViews[blockIndex], initVectorCBC, view.squareBlockViews[blockIndex - 1], K, SBox);
                    }
                    break;

                case OperationMode.OFB:
                    AESInputView128Bit initVectorViewOFB = new AESInputView128Bit(initialisationVector, OperationMode.OFB, 128);
                    AESInputViewSquareBlock curVectorBlockOFB = initVectorViewOFB.GetSquareBlock(0); //convert initialisation vector to a view (that way, it can be enciphered more easily)
                    for (int blockIndex = 0; blockIndex < view.SquareBlockCount; ++blockIndex)
                    {
                        curVectorBlockOFB = EncipherBlock_OFB(view.squareBlockViews[blockIndex], curVectorBlockOFB, K, SBox); //updates the vector block after each iteration
                    }
                    break;

                case OperationMode.CFB:
                    AESInputView128Bit initVectorViewCFB = new AESInputView128Bit(initialisationVector, OperationMode.CFB, 128);
                    AESInputViewSquareBlock curVectorBlockCFB = initVectorViewCFB.GetSquareBlock(0); //convert initialisation vector to a view (that way, it can be enciphered more easily)
                    for (int blockIndex = 0; blockIndex < view.SquareBlockCount; ++blockIndex)
                    {
                        curVectorBlockCFB = EncipherBlock_CFB(view.squareBlockViews[blockIndex], curVectorBlockCFB, K, SBox); //updates the vector block after each iteration
                    }
                    break;

                default:
                    throw new Exception("Unknown operation mode.");
            }

            //since all operations have been performed on the view classes (which route all operations to the output array), no further processing is needed. the ciphertext is already contained in output
            return output;
        }
        
        /// <summary>
        /// 
        /// </summary>
        /// <param name="input">The ciphertext that has been converted to an array of bytes</param>
        /// <param name="key">The key with which to decipher the input. It's length needs to be the same as byteCount.</param>
        /// <param name="mode">The mode of operation with which to decipher the input</param>
        /// <param name="byteCount">The block length used to decipher the input. Only 16 byte (128 bit) are supported at the moment.</param>
        /// <param name="operationBlockBitCount">Some modes of operation require a block length lower than or equal to byteCount during calculations. Again, only 128 bit are supported at the moment.</param>
        /// <param name="initialisationVector">Some modes of operation require an initialisation vector. The vector's length is either the same as byteCount or as operationBlockBitCount depending on the mode of operation.</param>
        /// <returns>Input deciphered with the given key</returns>
        private byte[] GetPlaintext_AES(byte[] input, int[] key, OperationMode mode, int byteCount, int operationBlockBitCount = 128, byte[] initialisationVector = null)
        {
            if (key.Length != 4)
            {
                throw new NotSupportedException("Only 128-bit keys are currently supported.");
            }

            byte[] output;
            if (input.Length % byteCount != 0) //ensure that input.Length is a multiple of byteCount!
            {
                Trace.WriteLine($"Applying padding ({input.Length} to {(int)Math.Ceiling((float)input.Length / byteCount) * byteCount} byte)...");
                output = new byte[(int)Math.Ceiling((float)input.Length / byteCount) * byteCount]; //pad to next multiple of byteCount
                Array.Copy(input, 0, output, 0, input.Length); //copy input to empty output. rest will be 0 (padding)
            }
            else
            {
                output = new byte[input.Length];
                Array.Copy(input, 0, output, 0, input.Length); //copy input to empty output. no padding required
            }

            AESInputView view = AESInputView.FromMode(output, 16, mode, operationBlockBitCount = 128); //automatically builds square block views. For functionality, see summary at the AESInputView class
            byte[] SBox = { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };
            byte[] inverseSBox = { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };
            byte[][] K = GetRoundKeys(key, 11, SBox); //11 round keys (use the original SBox, not the inverse one!)

            switch (mode)
            {
                case OperationMode.ECB:
                    for (int blockIndex = 0; blockIndex < view.SquareBlockCount; ++blockIndex)
                    {
                        DecipherBlock_ECB(view.squareBlockViews[blockIndex], K, inverseSBox);
                    }
                    break;

                case OperationMode.CBC:
                    byte[] initVectorCBC = initialisationVector;
                    for (int blockIndex = view.SquareBlockCount - 1; blockIndex > 0; --blockIndex) //reverse order
                    {
                        DecipherBlock_CBC(view.squareBlockViews[blockIndex], initVectorCBC, view.squareBlockViews[blockIndex - 1], K, inverseSBox);
                    }
                    DecipherBlock_CBC(view.squareBlockViews[0], initVectorCBC, null, K, inverseSBox); //no previous block during the last decryption
                    break;

                case OperationMode.OFB:
                    AESInputView128Bit initVectorViewOFB = new AESInputView128Bit(initialisationVector, OperationMode.OFB, 128);
                    AESInputViewSquareBlock curVectorBlockOFB = initVectorViewOFB.GetSquareBlock(0); //convert initialisation vector to a view (that way, it can be enciphered more easily)
                    for (int blockIndex = 0; blockIndex < view.SquareBlockCount; ++blockIndex)
                    {
                        curVectorBlockOFB = DecipherBlock_OFB(view.squareBlockViews[blockIndex], curVectorBlockOFB, K, SBox); //updates the vector block after each iteration
                    }
                    break;

                case OperationMode.CFB:
                    AESInputView128Bit initVectorViewCFB = new AESInputView128Bit(initialisationVector, OperationMode.CFB, 128);
                    AESInputViewSquareBlock initVectorBlockCFB = initVectorViewCFB.GetSquareBlock(0); //convert initialisation vector to a view (that way, it can be enciphered more easily)
                    AESInputViewSquareBlock curVectorBlockCFB; //used to get keys through previous cipher blocks - during deciphering, the block content is cloned so that the cipher block isn't changed
                    for (int blockIndex = view.SquareBlockCount - 1; blockIndex > 0; --blockIndex) //reverse order
                    {
                        curVectorBlockCFB = view.squareBlockViews[blockIndex - 1];
                        DecipherBlock_CFB(view.squareBlockViews[blockIndex], initVectorBlockCFB, curVectorBlockCFB, K, SBox);
                    }
                    DecipherBlock_CFB(view.squareBlockViews[0], initVectorBlockCFB, null, K, SBox); //no previous block during the last decryption
                    break;

                default:
                    throw new Exception("Unknown operation mode.");
            }

            //since all operations have been performed on the view classes (which route all operations to the output array), no further processing is needed. the ciphertext is already contained in output
            return output;
        }



        #region Views
        /// <summary>
        /// A class that handles the different representations of the AES input, e.g. as square matrices.
        /// 
        /// The idea is that, instead of copying the original array to a new representation for calculations and then back to the original array,
        /// this class will handle all the different representations by containing mappings corresponding to the representations.
        /// 
        /// E.g. AESInputView.squareBlockViews contains all square blocks, so instead of having to copy the input to square block representations,
        /// one can simply pass view.squareBlockViews[index] and use it like such a square block. Assigning values to an entry of the square block will then
        /// change the corresponding value in the original output.
        /// 
        /// This was originally important since some modes of operation have different block lengths from the AES block length,
        /// so this would be able to handle both the square blocks and those operation blocks at the same time without messy code.
        /// Since I've decided to only allow 128-bit operation blocks, this has become slightly redundant, but it can still be used to implement operation blocks later, so I left it in.
        /// 
        /// Also, it still improves the readability of the code (imo), so that's another plus.
        /// </summary>
        private abstract class AESInputView
        {
            protected byte[] data;
            public byte this[int index]
            {
                get => data[index];
                set => data[index] = value;
            }
            public int ByteCount
            {
                get => data.Length;
            }

            /// <summary>
            /// Array containing all square block representations of the given input. They act as mappings, so changing a value in one of the square blocks will change the original input.
            /// </summary>
            public AESInputViewSquareBlock[] squareBlockViews;
            public int SquareBlockCount
            {
                get => squareBlockViews.Length;
            }

            public OperationMode mode;
            //public AESInputViewOperationBlock[] operationBlockViews;
            //public int OperationBlockCount
            //{
            //    get => operationBlockViews.Length;
            //}

            protected AESInputView(byte[] data, int byteCount, OperationMode mode)
            {
                if (data.Length % byteCount != 0)
                {
                    throw new ArgumentException("Data cannot be divided according to the given byte count. Adjust the length of data to be a multiple of byteCount before making it a view to fix this.");
                }
                this.data = data;
                this.mode = mode;

                //squareBlockViews and operationBlockViews set in subclasses
            }
            public static AESInputView FromMode(byte[] data, int byteCount, OperationMode mode, int operationBlockBitCount = 128)
            {
                switch (byteCount)
                {
                    case 16: //128-bit
                        return new AESInputView128Bit(data, mode, operationBlockBitCount);

                    default:
                        throw new NotSupportedException("Only 128-bit AES is currently supported.");
                }
                
            }

            public AESInputViewSquareBlock GetSquareBlock(int blockIndex)
            {
                return squareBlockViews[blockIndex];
            }
            public void SetSquareBlock(int blockIndex, AESInputViewSquareBlock squareBlock)
            {
                squareBlockViews[blockIndex] = squareBlock;
            }
            public byte GetSquareBlockValue(int blockIndex, int columnIndex, int rowIndex)
            {
                return squareBlockViews[blockIndex][columnIndex, rowIndex];
            }
            public void SetSquareBlockValue(int blockIndex, int columnIndex, int rowIndex, byte value)
            {
                squareBlockViews[blockIndex][columnIndex, rowIndex] = value;
            }

            //v- currently obsolete, but could be used for additional features later
            //public AESInputViewOperationBlock GetOperationBlock(int blockIndex)
            //{
            //    return operationBlockViews[blockIndex];
            //}
            //public void SetOperationBlock(int blockIndex, AESInputViewOperationBlock operationBlock)
            //{
            //    operationBlockViews[blockIndex] = operationBlock;
            //}
            //public byte GetOperationBlockValue(int blockIndex, int index)
            //{
            //    return operationBlockViews[blockIndex][index];
            //}
            //public void SetOperationBlock(int blockIndex, int index, byte value)
            //{
            //    operationBlockViews[blockIndex][index] = value;
            //}

        }

        /// <summary>
        /// 128-bit version of AESInputView. Since the byte count (16) is a square number, we can implement the square block representations.
        /// </summary>
        private class AESInputView128Bit : AESInputView
        {
            public AESInputView128Bit(byte[] data, OperationMode mode, int bitCount = 128) : base(data, 16, mode)
            {
                //initialise square block views
                squareBlockViews = new AESInputViewSquareBlock128Bit[data.Length / 16];
                for (int blockIndex = 0; blockIndex < squareBlockViews.Length; ++blockIndex)
                {
                    squareBlockViews[blockIndex] = new AESInputViewSquareBlock128Bit(this, blockIndex); //initialises all mappings
                }

                ////initialise operation block views (currently obsolete)
                //operationBlockViews = new AESInputViewOperationBlock[AESInputViewOperationBlock.BlockCountFromMode(this, mode, bitCount)];
                //for (int blockIndex = 0; blockIndex < operationBlockViews.Length; ++blockIndex)
                //{
                //    operationBlockViews[blockIndex] = AESInputViewOperationBlock.FromMode(this, blockIndex, mode, bitCount);
                //}
            }
        }



        /// <summary>
        /// The square block representation of a given block of an input array.
        /// This class acts as a mapping, i.e. accessing AESInputViewSquareBlock[x,y] will get/set the corresponding values in the *original* input.
        /// </summary>
        private abstract class AESInputViewSquareBlock
        {
            protected AESInputView view;
            protected int blockIndex;

            protected int[,] indexMappings; //-> pre-calculate the mappings of all indices so that accessing them will be quicker in the long run

            public AESInputViewSquareBlock(AESInputView view, int blockIndex)
            {
                this.view = view;
                this.blockIndex = blockIndex;
                //indexMappings initialised in subclasses
            }

            public byte this[int indexX, int indexY]
            {
                get => view[indexMappings[indexX, indexY]]; //gets the corresponding value in the original input
                set => view[indexMappings[indexX, indexY]] = value; //sets the corresponding value in the original input
            }
            public virtual byte SideLength
            {
                get => throw new NotImplementedException("SideLength must be implemented in the subclasses of AESInputViewSquareBlock.");
            }

            /// <summary>
            /// Creates a copy of the corresponding input values of this square block and creates a square block view on that copy of the input. That means that accessing the cloned square block will not change values in the input of the original square block.
            /// </summary>
            /// <returns>Deep copy of this square block</returns>
            public abstract AESInputViewSquareBlock CloneContent();
        }

        /// <summary>
        /// 128-bit version of AESInputViewSquareBlock. Since the byte count (16) is a square number, we know the side length of the square block (4) and can calculate the mappings.
        /// </summary>
        private class AESInputViewSquareBlock128Bit : AESInputViewSquareBlock
        {
            public AESInputViewSquareBlock128Bit(AESInputView view, int blockIndex) : base(view, blockIndex)
            {
                //initialise index mappings
                indexMappings = new int[4, 4];
                for (int x = 0; x < SideLength; ++x)
                {
                    for (int y = 0; y < SideLength; ++y)
                    {
                        indexMappings[x, y] = blockIndex * 16 + x * 4 + y; //index in the original input (mapped column-wise)
                    }
                }
            }

            public override byte SideLength {
                get => 4;
            }

            public override AESInputViewSquareBlock CloneContent()
            {
                byte[] clonedBytes = new byte[SideLength * SideLength]; //only clone content of the square, not the rest of the view
                for (int x = 0; x < SideLength; ++x)
                {
                    for (int y = 0; y < SideLength; ++y)
                    {
                        clonedBytes[x * SideLength + y] = view[indexMappings[x, y]];
                    }
                }
                AESInputView clonedView = AESInputView.FromMode(clonedBytes, 16, view.mode); //only contains 1 square block - the cloned block
                return clonedView.GetSquareBlock(0);
            }
        }



        //v- currently obsolete, but can be used for additional features later on
        //private abstract class AESInputViewOperationBlock
        //{
        //    protected AESInputView view;
        //    protected int blockIndex;

        //    protected int[] indexMappings; //-> pre-calculate the values of all indices so that accessing them will be quicker in the long run

        //    public AESInputViewOperationBlock(AESInputView view, int blockIndex)
        //    {
        //        this.view = view;
        //        this.blockIndex = blockIndex;
        //        //indexMappings initialised in subclasses
        //    }
        //    public static AESInputViewOperationBlock FromMode(AESInputView view, int blockIndex, OperationMode mode, int bitCount = 128)
        //    {
        //        switch (mode)
        //        {
        //            case OperationMode.ECB:
        //            case OperationMode.CBC:
        //                return new AESInputViewOperationBlock128Bit(view, blockIndex);

        //            case OperationMode.OFB:
        //            case OperationMode.CFB:
        //                return new AESInputViewOperationBlockLBit(view, blockIndex, bitCount);

        //            default:
        //                throw new ArgumentException("Unknown operation mode.");
        //        }
        //    }
        //    public static int BlockCountFromMode(AESInputView view, OperationMode mode, int bitCount = 128)
        //    {
        //        switch (mode)
        //        {
        //            case OperationMode.ECB:
        //            case OperationMode.CBC:
        //                return (int)Math.Ceiling(view.ByteCount / 16f); //128-bit (8-byte) blocks

        //            case OperationMode.OFB:
        //            case OperationMode.CFB:
        //                return (int)Math.Ceiling((view.ByteCount * 8f) / bitCount); //l-bit blocks

        //            default:
        //                throw new ArgumentException("Unknown operation mode.");
        //        }
        //    }

        //    public virtual byte this[int index]
        //    {
        //        get => view[indexMappings[index]];
        //        set => view[indexMappings[index]] = value;
        //    }
        //}
        //private class AESInputViewOperationBlock128Bit : AESInputViewOperationBlock
        //{
        //    public AESInputViewOperationBlock128Bit(AESInputView view, int blockIndex) : base(view, blockIndex)
        //    {
        //        indexMappings = new int[16];
        //        for (int i = 0; i < 16; ++i)
        //        {
        //            indexMappings[i] = blockIndex * 16 + i;
        //        }
        //    }
        //}
        //private class AESInputViewOperationBlockLBit : AESInputViewOperationBlock
        //{
        //    private int bitCount; //l bit (NOTE: it seems that this is usually 1, 8, 64, 128, 192, 256 etc. - other values are rather unusual, so I will exclude them for simplicity)

        //    public AESInputViewOperationBlockLBit(AESInputView view, int blockIndex, int bitCount) : base(view, blockIndex)
        //    {
        //        if (bitCount != 128)
        //        {
        //            throw new NotSupportedException("Only 128 bit are currently supported as the operation block length.");
        //        }

        //        this.bitCount = bitCount;

        //        //128-bit:
        //        indexMappings = new int[16];
        //        for (int i = 0; i < 16; ++i)
        //        {
        //            indexMappings[i] = blockIndex * 16 + i;
        //        }
        //    }

        //    //v- override currently not necessary since the only supported length is 128 bit (and the property of the base class already supports that length)
        //    //public override byte this[int index]
        //    //{ }
        //}
        #endregion



        #region Getting round keys
        /// <summary>
        /// Calculates the round keys from the given key for the given number of rounds
        /// </summary>
        /// <param name="key">Key to encipher/decipher the input</param>
        /// <param name="count">Number of rounds</param>
        /// <param name="SBox">Array containing the substitutions of all possible byte values (the index acts as the input byte value)</param>
        /// <returns>Round keys created from the given key for the given number of rounds</returns>
        private byte[][] GetRoundKeys(int[] key, int count, byte[] SBox)
        {
            if (key.Length == 4) //128 bit key
            {
                int[][] outputInt = new int[count][]; //-> [roundIndex][roundKeyIndex]
                int totalKeyIndex; //there will be 4 keys per round - this keeps track of the total number of generated keys
                
                for (int round = 0; round < count; ++round)
                {
                    outputInt[round] = new int[4];
                    for (int roundKeyIndex = 0; roundKeyIndex < 4; ++roundKeyIndex) //4 round keys
                    {
                        totalKeyIndex = round * 4 + roundKeyIndex;
                        if (totalKeyIndex < 4)
                        {
                            outputInt[round][roundKeyIndex] = key[roundKeyIndex];
                        }
                        else
                        {
                            if (totalKeyIndex % 4 == 0)
                            {
                                outputInt[round][roundKeyIndex] = outputInt[(totalKeyIndex - 4) >> 2][(totalKeyIndex - 4) & 0x3]; //>> 2 is the same as /4, but faster. & 0x3 is the same as %4, but faster.
                                outputInt[round][roundKeyIndex] ^= GetRCon(totalKeyIndex >> 2); 
                                outputInt[round][roundKeyIndex] ^= SubWord(RotWord(outputInt[(totalKeyIndex - 1) >> 2][(totalKeyIndex - 1) & 0x3]), SBox);
                            }
                            else
                            {
                                outputInt[round][roundKeyIndex] = outputInt[(totalKeyIndex - 4) >> 2][(totalKeyIndex - 4) & 0x3] ^ outputInt[(totalKeyIndex - 1) >> 2][(totalKeyIndex - 1) & 0x3];
                            }
                        }
                    }
                }

                //convert int values to byte (the AES algorithm uses a byte array for keys instead of an int array)
                //to do so, each int value is split into its byte values, and all byte values are added to outputByte
                byte[][] outputByte = new byte[outputInt.GetLength(0)][]; //[roundIndex][roundByteKeyIndex]
                byte[] curBytes;
                for (int round = 0; round < count; ++round)
                {
                    outputByte[round] = new byte[outputInt[round].Length * 4];
                    for (int intIndex = 0; intIndex < outputInt[round].Length; ++intIndex)
                    {
                        curBytes = BitConverter.GetBytes(outputInt[round][intIndex]);
                        for (int byteIndex = 0; byteIndex < 4; ++byteIndex)
                        {
                            outputByte[round][intIndex * 4 + byteIndex] = curBytes[byteIndex];
                        }
                    }
                }

                return outputByte;
            }
            else
            {
                throw new NotImplementedException("Only 128-bit keys are currently supported.");
            }
        }



        /// <summary>
        /// Substitutes all byte values in the given 4-byte integer value
        /// </summary>
        /// <param name="input">Input that will be substituted</param>
        /// <param name="SBox">Array containing the substitutions of all possible byte values (the index acts as the input byte value)</param>
        /// <returns>Input with all byte values substituted</returns>
        private int SubWord(int input, byte[] SBox)
        {
            byte[] output = BitConverter.GetBytes(input); //convert word into bytes
            
            //substitute bytes
            for (int i = 0; i < output.Length; ++i)
            {
                output[i] = SBox[output[i]];
            }

            return BitConverter.ToInt32(output); //convert bytes back to word
        }
        
        /// <summary>
        /// Shifts all byte values in the given 4-byte integer value one byte to the left
        /// </summary>
        /// <param name="input">Input that will be rotated</param>
        /// <returns>Input with all byte values rotated by one byte to the left</returns>
        private int RotWord(int input)
        {
            int output = input << 8; //shift one word to the left

            //append original leftmost byte at the 8 rightmost bits of the output
            output |= (input >> 24) & 0xFF;

            return output;
        }

        /// <summary>
        /// Gets the round constant for the given round.
        /// </summary>
        /// <param name="i">Round number (must be larger than 0)</param>
        /// <returns>Round constant for the given round</returns>
        private int GetRCon(int i)
        {
            byte rc = 0x01;

            for (int j = 2; j <= i; ++j)
            {
                rc = XTime(rc);
            }

            byte[] rcon = { rc, 0x0, 0x0, 0x0 };

            return BitConverter.ToInt32(rcon);
        }
        #endregion



        #region Enciphering/Deciphering modes
        /// <summary>
        /// Enciphers a square block of bytes in ECB (electronic code book) mode.
        /// </summary>
        /// <param name="inputSquareBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        /// <param name="K">Array containing the round keys for the encryption</param>
        /// <param name="SBox">Array containing the substitutions of all possible byte values (the index acts as the input byte value)</param>
        private void EncipherBlock_ECB(AESInputViewSquareBlock inputSquareBlock, byte[][] K, byte[] SBox)
        {
            EncipherBlock_AES(inputSquareBlock, K, SBox);
        }

        /// <summary>
        /// Enciphers a square block of bytes in CBC (cipher block chaining) mode.
        /// </summary>
        /// <param name="inputSquareBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        /// <param name="initialisationVector">Initialisation vector that is used to XOR the first square block instead of a preceding cipher block</param>
        /// <param name="previousCipherSquareBlock">The square block before inputSquareBlock that has already been enciphered. Its values won't be changed, they are only XORed onto the plaintext.</param>
        /// <param name="K">Array containing the round keys for the encryption</param>
        /// <param name="SBox">Array containing the substitutions of all possible byte values (the index acts as the input byte value)</param>
        private void EncipherBlock_CBC(AESInputViewSquareBlock inputSquareBlock, byte[] initialisationVector, AESInputViewSquareBlock previousCipherSquareBlock, byte[][] K, byte[] SBox)
        {
            if (previousCipherSquareBlock == null)
            {
                //first inputBlock -> XOR with initialisation vector
                for (int columnIndex = 0; columnIndex < inputSquareBlock.SideLength; ++columnIndex)
                {
                    for (int rowIndex = 0; rowIndex < inputSquareBlock.SideLength; ++rowIndex)
                    {
                        inputSquareBlock[columnIndex, rowIndex] ^= initialisationVector[columnIndex * inputSquareBlock.SideLength + rowIndex];
                    }
                }
            }
            else
            {
                //XOR inputBlock with previous cipher block
                for (int columnIndex = 0; columnIndex < inputSquareBlock.SideLength; ++columnIndex)
                {
                    for (int rowIndex = 0; rowIndex < inputSquareBlock.SideLength; ++rowIndex)
                    {
                        inputSquareBlock[columnIndex, rowIndex] ^= previousCipherSquareBlock[columnIndex, rowIndex];
                    }
                }
            }

            EncipherBlock_AES(inputSquareBlock, K, SBox);
        }

        /// <summary>
        /// Enciphers a square block of bytes in OFB (output feedback) mode.
        /// </summary>
        /// <param name="inputSquareBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        /// <param name="curInitialisationVector">The initialisation vector used to encipher the plaintext. Since the vector is encrypted many times, it's given as a square block itself.</param>
        /// <param name="K">Array containing the round keys for the encryption</param>
        /// <param name="SBox">Array containing the substitutions of all possible byte values (the index acts as the input byte value)</param>
        /// <returns>Enciphered curInitialisationVector. It is needed for the next input square block.</returns>
        private AESInputViewSquareBlock EncipherBlock_OFB(AESInputViewSquareBlock inputSquareBlock, AESInputViewSquareBlock curInitialisationVector, byte[][] K, byte[] SBox)
        {
            //encipher *initialisation vector*
            EncipherBlock_AES(curInitialisationVector, K, SBox);

            //XOR to plaintext
            for (int columnIndex = 0; columnIndex < inputSquareBlock.SideLength; ++columnIndex)
            {
                for (int rowIndex = 0; rowIndex < inputSquareBlock.SideLength; ++rowIndex)
                {
                    inputSquareBlock[columnIndex, rowIndex] ^= curInitialisationVector[columnIndex, rowIndex];
                }
            }

            return curInitialisationVector; //return enciphered initialisation vector (required for next block)
        }

        /// <summary>
        /// Enciphers a square block of bytes in CFB (cipher feedback) mode.
        /// </summary>
        /// <param name="inputSquareBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        /// <param name="curInitialisationVector">The initialisation vector or ciphertext used to encipher the plaintext. Since this value is encrypted many times, it's given as a square block itself.</param>
        /// <param name="K">Array containing the round keys for the encryption</param>
        /// <param name="SBox">Array containing the substitutions of all possible byte values (the index acts as the input byte value)</param>
        /// <returns>Clone of the enciphered inputSquareBlock. It is needed for the next input square block.</returns>
        private AESInputViewSquareBlock EncipherBlock_CFB(AESInputViewSquareBlock inputSquareBlock, AESInputViewSquareBlock curInitialisationVector, byte[][] K, byte[] SBox)
        {
            //encipher *initialisation vector*
            EncipherBlock_AES(curInitialisationVector, K, SBox);

            //XOR to plaintext
            for (int columnIndex = 0; columnIndex < inputSquareBlock.SideLength; ++columnIndex)
            {
                for (int rowIndex = 0; rowIndex < inputSquareBlock.SideLength; ++rowIndex)
                {
                    inputSquareBlock[columnIndex, rowIndex] ^= curInitialisationVector[columnIndex, rowIndex];
                }
            }

            return inputSquareBlock.CloneContent(); //return cipher block (required for next block)
        }



        /// <summary>
        /// Deciphers a square block of bytes in ECB (electronic code book) mode.
        /// </summary>
        /// <param name="inputSquareBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        /// <param name="K">Array containing the round keys for the decryption</param>
        /// <param name="inverseSBox">Array containing the substitutions of all possible byte values (the index acts as the input byte value)</param>
        private void DecipherBlock_ECB(AESInputViewSquareBlock inputSquareBlock, byte[][] K, byte[] inverseSBox)
        {
            DecipherBlock_AES(inputSquareBlock, K, inverseSBox);
        }

        /// <summary>
        /// Deciphers a square block of bytes in CBC (cipher block chaining) mode.
        /// </summary>
        /// <param name="inputSquareBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        /// <param name="initialisationVector">Initialisation vector that is used to XOR the first square block instead of a preceding cipher block</param>
        /// <param name="previousCipherSquareBlock">The square block before inputSquareBlock that has been enciphered. Its values won't be changed, they are only XORed onto the ciphertext.</param>
        /// <param name="K">Array containing the round keys for the decryption</param>
        /// <param name="inverseSBox">Array containing the substitutions of all possible byte values (the index acts as the input byte value)</param>
        private void DecipherBlock_CBC(AESInputViewSquareBlock inputSquareBlock, byte[] initialisationVector, AESInputViewSquareBlock previousCipherSquareBlock, byte[][] K, byte[] inverseSBox)
        {
            DecipherBlock_AES(inputSquareBlock, K, inverseSBox);

            if (previousCipherSquareBlock == null)
            {
                //first inputBlock -> XOR with initialisation vector
                for (int columnIndex = 0; columnIndex < inputSquareBlock.SideLength; ++columnIndex)
                {
                    for (int rowIndex = 0; rowIndex < inputSquareBlock.SideLength; ++rowIndex)
                    {
                        inputSquareBlock[columnIndex, rowIndex] ^= initialisationVector[columnIndex * inputSquareBlock.SideLength + rowIndex];
                    }
                }
            }
            else
            {
                //XOR inputBlock with previous cipher block
                for (int columnIndex = 0; columnIndex < inputSquareBlock.SideLength; ++columnIndex)
                {
                    for (int rowIndex = 0; rowIndex < inputSquareBlock.SideLength; ++rowIndex)
                    {
                        inputSquareBlock[columnIndex, rowIndex] ^= previousCipherSquareBlock[columnIndex, rowIndex];
                    }
                }
            }
        }

        /// <summary>
        /// Deciphers a square block of bytes in OFB (output feedback) mode.
        /// </summary>
        /// <param name="inputSquareBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        /// <param name="curInitialisationVector">The initialisation vector used to decipher the plaintext. Since the vector is encrypted many times, it's given as a square block itself.</param>
        /// <param name="K">Array containing the round keys for the decryption</param>
        /// <param name="SBox">Array containing the substitutions of all possible byte values (the index acts as the input byte value)</param>
        /// <returns>Enciphered (not deciphered!) curInitialisationVector. It is needed for the next input square block.</returns>
        private AESInputViewSquareBlock DecipherBlock_OFB(AESInputViewSquareBlock inputSquareBlock, AESInputViewSquareBlock curInitialisationVector, byte[][] K, byte[] SBox)
        {
            //encipher *initialisation vector*
            EncipherBlock_AES(curInitialisationVector, K, SBox); //note: encryption used during deciphering, too!

            //XOR to ciphertext
            for (int columnIndex = 0; columnIndex < inputSquareBlock.SideLength; ++columnIndex)
            {
                for (int rowIndex = 0; rowIndex < inputSquareBlock.SideLength; ++rowIndex)
                {
                    inputSquareBlock[columnIndex, rowIndex] ^= curInitialisationVector[columnIndex, rowIndex];
                }
            }

            return curInitialisationVector; //return enciphered initialisation vector (required for next block)
        }

        /// <summary>
        /// Enciphers a square block of bytes in CFB (cipher feedback) mode.
        /// </summary>
        /// <param name="inputSquareBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        /// <param name="initialisationVector">The initialisation vector used to decipher the ciphertext. Since this value will be encrypted, it's given as a square block itself.</param>
        /// <param name="previousCipherSquareBlock">Clone of the previous ciphertext block used to decipher the plaintext. Since this value will be encrypted, it's given as a square block itself.</param>
        /// <param name="K">Array containing the round keys for the decryption</param>
        /// <param name="SBox">Array containing the substitutions of all possible byte values (the index acts as the input byte value)</param>
        private void DecipherBlock_CFB(AESInputViewSquareBlock inputSquareBlock, AESInputViewSquareBlock initialisationVector, AESInputViewSquareBlock previousCipherSquareBlock, byte[][] K, byte[] SBox)
        {
            if (previousCipherSquareBlock == null)
            {
                //encipher *initialisation vector*
                EncipherBlock_AES(initialisationVector, K, SBox); //note: encryption used during deciphering, too!

                //XOR to plaintext
                for (int columnIndex = 0; columnIndex < inputSquareBlock.SideLength; ++columnIndex)
                {
                    for (int rowIndex = 0; rowIndex < inputSquareBlock.SideLength; ++rowIndex)
                    {
                        inputSquareBlock[columnIndex, rowIndex] ^= initialisationVector[columnIndex, rowIndex];
                    }
                }
            }
            else
            {
                //encipher previous cipher square block
                AESInputViewSquareBlock prevSquareBlockClone = previousCipherSquareBlock.CloneContent(); //clone previous cipher block so that the original cipher text isn't changed through the following encryption!
                EncipherBlock_AES(prevSquareBlockClone, K, SBox); //note: encryption used during deciphering, too!

                //XOR to plaintext
                for (int columnIndex = 0; columnIndex < inputSquareBlock.SideLength; ++columnIndex)
                {
                    for (int rowIndex = 0; rowIndex < inputSquareBlock.SideLength; ++rowIndex)
                    {
                        inputSquareBlock[columnIndex, rowIndex] ^= prevSquareBlockClone[columnIndex, rowIndex];
                    }
                }
            }
        }
        #endregion



        #region Enciphering/Deciphering a single block
        /// <summary>
        /// Enciphers the given input block using the Advanced Encryption Standard algorithm
        /// </summary>
        /// <param name="inputBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        /// <param name="K">Array containing the round keys for the encryption</param>
        /// <param name="SBox">Array containing the substitutions of all possible byte values (the index acts as the input byte value)</param>
        private void EncipherBlock_AES(AESInputViewSquareBlock inputBlock, byte[][] K, byte[] SBox)
        {
            int roundCount = K.GetLength(0);

            AddRoundKey(inputBlock, K[0]);

            for (int i = 1; i < roundCount - 1; ++i)
            {
                SubBytes(inputBlock, SBox);
                ShiftRowsLeft(inputBlock);
                MixColumns(inputBlock);
                AddRoundKey(inputBlock, K[i]);
            }

            SubBytes(inputBlock, SBox);
            ShiftRowsLeft(inputBlock);
            AddRoundKey(inputBlock, K[roundCount - 1]);
        }

        /// <summary>
        /// Deciphers the given input block using the Advanced Encryption Standard algorithm
        /// </summary>
        /// <param name="inputBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        /// <param name="K">Array containing the round keys for the encryption</param>
        /// <param name="inverseSBox">Array containing the substitutions of all possible byte values (the index acts as the input byte value)</param>
        private void DecipherBlock_AES(AESInputViewSquareBlock inputBlock, byte[][] K, byte[] inverseSBox)
        {
            int roundCount = K.GetLength(0);

            SubtractRoundKey(inputBlock, K[roundCount - 1]);
            ShiftRowsRight(inputBlock);
            SubBytes(inputBlock, inverseSBox);

            for (int i = roundCount - 2; i > 0; --i)
            {
                SubtractRoundKey(inputBlock, K[i]);
                UnmixColumns(inputBlock);
                ShiftRowsRight(inputBlock);
                SubBytes(inputBlock, inverseSBox);
            }

            SubtractRoundKey(inputBlock, K[0]);
        }



        /// <summary>
        /// Adds the given round key to the given input block
        /// </summary>
        /// <param name="inputBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        /// <param name="K">Array containing the round keys for the encryption</param>
        private void AddRoundKey(AESInputViewSquareBlock inputBlock, byte[] K)
        {
            for (int columnIndex = 0; columnIndex < inputBlock.SideLength; ++columnIndex)
            {
                for (int rowIndex = 0; rowIndex < inputBlock.SideLength; ++rowIndex)
                {
                    inputBlock[columnIndex, rowIndex] ^= K[columnIndex * inputBlock.SideLength + rowIndex]; //read column-wise and apply XOR
                }
            }
        }

        /// <summary>
        /// Subtracts the given round key from the given input block. Since this is achieved through XORing, this is the same as addition (but using the different name makes the code more understandable).
        /// </summary>
        /// <param name="inputBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        /// <param name="K">Array containing the round keys for the encryption</param>
        private void SubtractRoundKey(AESInputViewSquareBlock inputBlock, byte[] K)
        {
            AddRoundKey(inputBlock, K); //since the addition is implemented through an XOR, subtraction is the same as addition in this case
        }

        /// <summary>
        /// Substitutes all bytes in the given input block
        /// </summary>
        /// <param name="inputBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        /// <param name="SBox">Array containing the substitutions of all possible byte values (the index acts as the input byte value)</param>
        private void SubBytes(AESInputViewSquareBlock inputBlock, byte[] SBox)
        {
            for (int rowIndex = 0; rowIndex < inputBlock.SideLength; ++rowIndex)
            {
                for (int columnIndex = 0; columnIndex < inputBlock.SideLength; ++columnIndex)
                {
                    inputBlock[columnIndex, rowIndex] = SBox[inputBlock[columnIndex, rowIndex]]; //interpret entry as a number -> substitute by entry of the S-box at the number's index
                }
            }
        }

        /// <summary>
        /// Shifts all rows in the given input square block to the left according to their row index (the 0-th row is not shifted, the 1st by one column, etc.)
        /// </summary>
        /// <param name="inputBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        private void ShiftRowsLeft(AESInputViewSquareBlock inputBlock)
        {
            for (int rowIndex = 1; rowIndex < inputBlock.SideLength; ++rowIndex) //first row doesn't change, so it's omitted
            {
                //rotate column entries by rowIndex blocks left (-> cyclic shift)
                int shiftAmount = rowIndex;
                byte[] rowCopy = new byte[inputBlock.SideLength];
                for (int columnIndex = 0; columnIndex < inputBlock.SideLength; ++columnIndex)
                {
                    rowCopy[columnIndex] = inputBlock[columnIndex, rowIndex];
                }
                for (int columnIndex = 0; columnIndex < inputBlock.SideLength; ++columnIndex)
                {
                    inputBlock[columnIndex, rowIndex] = rowCopy[(columnIndex + shiftAmount) % inputBlock.SideLength];
                }
            }
        }

        /// <summary>
        /// Shifts all rows in the given input square block to the right according to their row index (the 0-th row is not shifted, the 1st by one column, etc.)
        /// </summary>
        /// <param name="inputBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        private void ShiftRowsRight(AESInputViewSquareBlock inputBlock)
        {
            for (int rowIndex = 1; rowIndex < inputBlock.SideLength; ++rowIndex) //first row doesn't change, so it's omitted
            {
                //rotate column entries by rowIndex blocks right (-> cyclic shift)
                int shiftAmount = rowIndex;
                byte[] rowCopy = new byte[inputBlock.SideLength];
                for (int columnIndex = 0; columnIndex < inputBlock.SideLength; ++columnIndex)
                {
                    rowCopy[columnIndex] = inputBlock[columnIndex, rowIndex];
                }
                for (int columnIndex = inputBlock.SideLength - 1; columnIndex >= 0; --columnIndex)
                {
                    inputBlock[columnIndex, rowIndex] = rowCopy[(columnIndex - shiftAmount + inputBlock.SideLength) % inputBlock.SideLength];
                }
            }
        }

        /// <summary>
        /// Treating the byte values of the given input block as polynomes, multiplies each column of the input block with a given matrix to mix the columns with each other
        /// </summary>
        /// <param name="inputBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        private void MixColumns(AESInputViewSquareBlock inputBlock)
        {
            byte c0, c1, c2, c3, newC0, newC1, newC2, newC3; //old and new column values (with indices)
            for (int columnIndex = 0; columnIndex < inputBlock.SideLength; ++columnIndex)
            {
                c0 = inputBlock[columnIndex, 0];
                c1 = inputBlock[columnIndex, 1];
                c2 = inputBlock[columnIndex, 2];
                c3 = inputBlock[columnIndex, 3];

                newC0 = (byte)((MultiplyPolynoms(0x2, c0) ^ MultiplyPolynoms(0x3, c1) ^ MultiplyPolynoms(0x1, c2) ^ MultiplyPolynoms(0x1, c3)) & 0xFF);
                newC1 = (byte)((MultiplyPolynoms(0x1, c0) ^ MultiplyPolynoms(0x2, c1) ^ MultiplyPolynoms(0x3, c2) ^ MultiplyPolynoms(0x1, c3)) & 0xFF);
                newC2 = (byte)((MultiplyPolynoms(0x1, c0) ^ MultiplyPolynoms(0x1, c1) ^ MultiplyPolynoms(0x2, c2) ^ MultiplyPolynoms(0x3, c3)) & 0xFF);
                newC3 = (byte)((MultiplyPolynoms(0x3, c0) ^ MultiplyPolynoms(0x1, c1) ^ MultiplyPolynoms(0x1, c2) ^ MultiplyPolynoms(0x2, c3)) & 0xFF);

                inputBlock[columnIndex, 0] = newC0;
                inputBlock[columnIndex, 1] = newC1;
                inputBlock[columnIndex, 2] = newC2;
                inputBlock[columnIndex, 3] = newC3;
            }
        }

        /// <summary>
        /// Treating the byte values of the given input block as polynomes, multiplies each column of the input block with a given matrix (the inverse of the matrix used to mix them) to un-mix the columns with each other
        /// </summary>
        /// <param name="inputBlock">Square block view on the block of the input. This variable can be handled just like an array and will change the corresponding values in the input array.</param>
        private void UnmixColumns(AESInputViewSquareBlock inputBlock)
        {
            byte c0, c1, c2, c3, newC0, newC1, newC2, newC3; //old and new column values (with indices)
            for (int columnIndex = 0; columnIndex < inputBlock.SideLength; ++columnIndex)
            {
                c0 = inputBlock[columnIndex, 0];
                c1 = inputBlock[columnIndex, 1];
                c2 = inputBlock[columnIndex, 2];
                c3 = inputBlock[columnIndex, 3];

                newC0 = (byte)((MultiplyPolynoms(0xE, c0) ^ MultiplyPolynoms(0xB, c1) ^ MultiplyPolynoms(0xD, c2) ^ MultiplyPolynoms(0x9, c3)) & 0xFF);
                newC1 = (byte)((MultiplyPolynoms(0x9, c0) ^ MultiplyPolynoms(0xE, c1) ^ MultiplyPolynoms(0xB, c2) ^ MultiplyPolynoms(0xD, c3)) & 0xFF);
                newC2 = (byte)((MultiplyPolynoms(0xD, c0) ^ MultiplyPolynoms(0x9, c1) ^ MultiplyPolynoms(0xE, c2) ^ MultiplyPolynoms(0xB, c3)) & 0xFF);
                newC3 = (byte)((MultiplyPolynoms(0xB, c0) ^ MultiplyPolynoms(0xD, c1) ^ MultiplyPolynoms(0x9, c2) ^ MultiplyPolynoms(0xE, c3)) & 0xFF);

                inputBlock[columnIndex, 0] = newC0;
                inputBlock[columnIndex, 1] = newC1;
                inputBlock[columnIndex, 2] = newC2;
                inputBlock[columnIndex, 3] = newC3;
            }
        }

        private const byte m = 0x1b; //(x^8 +) x^4 + x^3 + x + 1 -> degrees (bits) 0 to 7 are sufficient since the reduced polynoms are only of degrees 7 and lower

        /// <summary>
        /// Treats the two input bytes as polynoms and multiplies them modulo m. The algorithm is analogous to Russian peasant multiplication (see https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field for details).
        /// </summary>
        /// <param name="x1">The first input byte (polynom)</param>
        /// <param name="x2">The second input byte (polynom)</param>
        /// <returns>The product of the two input bytes treated as polynoms modulo m</returns>
        private byte MultiplyPolynoms(byte x1, byte x2)
        {
            byte output = 0;

            //the following invariant is always true: x1 * x*2 + output is the product. at the start, output is 0, and at the end, x1 or x2 is zero.
            while (x1 > 0 && x2 > 0)
            {
                if ((x2 & 0x1) == 1) //if x2 is odd
                {
                    output ^= x1; //add current x1 to the output (XOR for addition of polynomials)
                }
                x1 = XTime(x1); //multiply x1 by x (automatically handles modulo)
                x2 >>= 1; //divide x2 by x (ignoring the x^0 term)
            }

            return output;
        }

        /// <summary>
        /// Treats the input byte as a polynom, multiplies it by x and is then taken modulo m.
        /// </summary>
        /// <param name="input">Input byte (polynom)</param>
        /// <returns>Input polynom multiplied by x and then taken modulo m</returns>
        private byte XTime(byte input) //doubles the input (-> polynome multiplied by x) while respecting modulo
        {
            int t = input << 1; //multiply polynom by x (-> double the byte representation)
            if (input >> 7 != 0) //if polynom has powers of x that are 8 or greater
            {
                t = t ^ m; //subtract m (-> basically modulo)
            }
            return (byte)(t & 0xFF); //cut off leading bits (the reduced polynoms are always of degree <8)
        }
        #endregion

        #endregion



        #region Import/Export
        private async void cmdImport_Click(object sender, RoutedEventArgs e)
        {
            //get file
            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == true)
            {
                try
                {
                    //open file
                    using (StreamReader sr = new StreamReader(ofd.FileName, Encoding.UTF8))
                    {
                        //read full file
                        tbInput.Text = await sr.ReadToEndAsync();
                        tbOutput.Text = "";
                    }
                    MessageBox.Show("The text file has been imported successfully.", "Imported from .txt file", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"The file could not be imported. Reason:\n{ex.Message}", "An error has occurred.", MessageBoxButton.OK, MessageBoxImage.Error);
                    Trace.WriteLine($"{ex.Message}\n{ex.StackTrace}\n{ex.InnerException}");
                }
            }
        }

        private async void cmdExport_Click(object sender, RoutedEventArgs e)
        {
            //only export if there is an output
            if (tbOutput.Text == "")
            {
                MessageBox.Show("There is currently no output to export.", "No output text detected.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                return;
            }

            //select file name and directory
            SaveFileDialog sfd = new SaveFileDialog()
            {
                DefaultExt = ".txt"
            };
            if (sfd.ShowDialog() == true)
            {
                try
                {
                    //open stream to write file
                    using (StreamWriter sw = new StreamWriter(sfd.FileName, append: false, Encoding.UTF8))
                    {
                        //write full output
                        await sw.WriteAsync(tbOutput.Text);
                    }
                    MessageBox.Show("The text file has been exported successfully.", "Exported to .txt file", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"The file could not be exported. Reason:\n{ex.Message}", "An error has occurred.", MessageBoxButton.OK, MessageBoxImage.Error);
                    Trace.WriteLine($"{ex.Message}\n{ex.StackTrace}\n{ex.InnerException}");
                }
            }
        }
        #endregion





        #region Other
        #region CBC-MAC
        //private ushort CBC_MAC(byte[] key, AESInputView x)
        //{
        //    ushort[] ciphertext = AES_Encipher_CBC(key, x);
        //    return ciphertext[ciphertext.Length - 1]; //the last block is regarded as a hash value and returned
        //}
        #endregion

        #region CCM
        //private byte[] CCM_Encrypt(AESInputView plaintextView, byte[][] K, byte[] SBox, byte nOnce)
        //{
        //    ushort ctr = nOnce; //64 bit; form: nOnce||0...0 (but in little endian)

        //    ushort[] T = new ushort[plaintextView.SquareBlockCount];
        //    ushort[] y = new ushort[plaintextView.SquareBlockCount - 1];
        //    T[0] = (ushort)(((uint)ctr + 0) % ((uint)ushort.MaxValue + 1));
        //    for (int i = 1; i < plaintextView.SquareBlockCount; i++)
        //    {
        //        T[i] = (ushort)(((uint)ctr + i) % ((uint)ushort.MaxValue + 1));
        //        y[i - 1] = plaintextView.squareBlockViews[i] ^ EncipherBlock_CBC(T[i], new byte[] { }, T[i - 1], K, SBox);
        //    }

        //    ushort tmp = BitConverter.ToUInt16(CBC_MAC(k, plaintextView));
        //    ushort yDash = (ushort)(((uint)T[0] ^ tmp) & 0x1111); //authenticator

        //    byte[] output = new byte[y.Length * 2 + 2]; //2 byte per y, 2 additional byte for yDash
        //    byte[] curYBytes;
        //    for (int i = 0; i < plaintextView.SquareBlockCount - 1; i++)
        //    {
        //        curYBytes = BitConverter.GetBytes(y[i]);
        //        Array.Reverse(curYBytes); //to big endian
        //        output[2 * i + 0] = curYBytes[0];
        //        output[2 * i + 1] = curYBytes[1];
        //    }
        //    curYBytes = BitConverter.GetBytes(yDash);
        //    Array.Reverse(curYBytes); //to big endian
        //    output[output.Length - 2] = curYBytes[0];
        //    output[output.Length - 1] = curYBytes[1];

        //    return output;
        //}

        //private ushort[] CCM_Decrypt(byte[] ciphertext, byte[][] K, byte[] SBox, byte nOnce)
        //{
        //    byte[] curYBytes = new byte[2];
        //    ushort yDash;
        //    curYBytes[0] = ciphertext[ciphertext.Length - 2];
        //    curYBytes[1] = ciphertext[ciphertext.Length - 1];
        //    Array.Reverse(curYBytes); //to little endian
        //    yDash = BitConverter.ToUInt16(curYBytes);

        //    ushort[] y = new ushort[(ciphertext.Length - 2) / 2];
        //    for (int i = 0; i < y.Length; i++)
        //    {
        //        curYBytes[0] = ciphertext[2 * i + 0];
        //        curYBytes[1] = ciphertext[2 * i + 1];
        //        Array.Reverse(curYBytes); //to little endian
        //        y[i] = BitConverter.ToUInt16(curYBytes);
        //    }

        //    ushort ctr = nOnce; //64 bit; form: nOnce||0...0 (but in little endian)
        //    ushort[] T = new ushort[y.Length + 1];
        //    ushort[] x = new ushort[y.Length];
        //    T[0] = (ushort)(((uint)ctr + 0) % ((uint)ushort.MaxValue + 1));
        //    for (int i = 1; i < T.Length; i++)
        //    {
        //        T[i] = (ushort)(((uint)ctr + i) % ((uint)ushort.MaxValue + 1));
        //    }
        //    for (int i = y.Length - 1; i > 0; i--)
        //    {
        //        x[i] = y[i] ^ DecipherBlock_CBC(T[i], new byte[] { }, T[i - 1], K, SBox);
        //    }

        //    ushort mac = BitConverter.ToUInt16(CBC_MAC(k, x));
        //    ushort verif = (ushort)(((uint)yDash ^ T[0]) & 0xFFFF);
        //    if (mac != verif)
        //    {
        //        throw new CryptographicException("The authentication is invalid!");
        //    }
        //    else
        //    {
        //        return x;
        //    }
        //}
        #endregion
        #endregion
    }
}
