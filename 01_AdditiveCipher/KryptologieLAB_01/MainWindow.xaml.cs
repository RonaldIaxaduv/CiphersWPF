using System;
using System.Collections.Generic;
using System.Windows;
using System.Text; //encoding
using System.Diagnostics; //debug output
using System.IO; //stream reader/writer
using Microsoft.Win32; //open/save file dialog

namespace KryptologieLAB_01
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
        /// Ensures that all inputs in the window that are required for encrypting/decrypting are set and valid. If any input is missing or invalid, a MessageBox is displayed.
        /// </summary>
        /// <param name="keyRequired">
        /// States whether a key is required for the operation. A key is not required for the automatic decryption.
        /// </param>
        /// <returns></returns>
        private bool CheckInputsAreValid(bool keyRequired)
        {
            //check for empty textboxes
            if (tbInput.Text == "")
            {
                MessageBox.Show("Please enter a text.", "No input detected.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                return false;
            }
            if (tbKey.Text == "")
            {
                MessageBox.Show("Please enter a key (integer between 0 and 127).", "No key detected.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                return false;
            }

            //check key
            if (keyRequired)
            {
                int key;
                try
                {
                    key = int.Parse(tbKey.Text);
                }
                catch (Exception)
                {
                    MessageBox.Show("The key must be an integer value (between 0 and 127).", "Key is not an integer.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                    return false;
                }
                if (!(0 <= key && key < 128))
                {
                    MessageBox.Show("The key must be an integer value between 0 and 127.", "Key is out of range.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                    return false;
                }
            }

            //no missing/invalid inputs detected
            return true;
        }

        #region 1) Encipher/decipher with key
        private void cmdEncipherKey_Click(object sender, RoutedEventArgs e)
        {
            if (!CheckInputsAreValid(keyRequired:true))
            {
                return;
            }

            tbOutput.Text = GetCiphertext_AdditiveCipher(tbInput.Text, int.Parse(tbKey.Text));

            MessageBox.Show("The text has been enciphered.", "Text has been enciphered.", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void cmdDecypherKey_Click(object sender, RoutedEventArgs e)
        {
            if (!CheckInputsAreValid(keyRequired: true))
            {
                return;
            }

            tbOutput.Text = GetPlaintext_AdditiveCipher(tbInput.Text, int.Parse(tbKey.Text));

            MessageBox.Show("The text has been deciphered.", "Text has been deciphered.", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        /// <summary>
        /// Calculates the ciphertext of the given text with an additive cipher.
        /// </summary>
        /// <param name="input">The text that will be enciphered. Required format: 7-bit ASCII.</param>
        /// <param name="key">A value between 0 and 127 used to encipher the text.</param>
        /// <returns>Input text enciphered with the given key.</returns>
        private string GetCiphertext_AdditiveCipher(string input, int key)
        {
            byte[] inputBytes = Encoding.ASCII.GetBytes(input);
            byte[] cipheredInput = new byte[input.Length];

            for (int i = 0; i < input.Length; ++i)
            {
                //shift character value by key and wrap by using modulo
                cipheredInput[i] = (byte)((inputBytes[i] + key) % 128);
                //Trace.WriteLine($"Shifted {inputBytes[i]} ({Encoding.ASCII.GetString(new byte[] { inputBytes[i] })}) to {cipheredInput[i]} ({Encoding.ASCII.GetString(new byte[] { cipheredInput[i] })}).");
            }

            return Encoding.ASCII.GetString(cipheredInput);
        }

        /// <summary>
        /// Calculates the plaintext of the given text with an additive cipher.
        /// </summary>
        /// <param name="input">The text that will be deciphered. Required format: 7-bit ASCII.</param>
        /// <param name="key">A value between 0 and 127 used to encipher the text.</param>
        /// <returns>Input text deciphered with the given key.</returns>
        private string GetPlaintext_AdditiveCipher(string input, int key)
        {
            byte[] inputBytes = Encoding.ASCII.GetBytes(input);
            byte[] cipheredInput = new byte[input.Length];

            for (int i = 0; i < input.Length; ++i)
            {
                cipheredInput[i] = (byte)((inputBytes[i] - key + 128) % 128); //"key" difference: subtraction instead of addition
                //Trace.WriteLine($"Shifted {inputBytes[i]} ({Encoding.ASCII.GetString(new byte[] { inputBytes[i] })}) to {cipheredInput[i]} ({Encoding.ASCII.GetString(new byte[] { cipheredInput[i] })}).");
            }

            return Encoding.ASCII.GetString(cipheredInput);
        }
        #endregion

        #region 2) Decipher automatically
        private void cmdDecipherAuto_Click(object sender, RoutedEventArgs e)
        {
            if (!CheckInputsAreValid(keyRequired: false))
            {
                return;
            }

            int key = GetKeyThroughFrequencies(tbInput.Text);
            tbKey.Text = key.ToString(); //display key in textbox

            tbOutput.Text = GetPlaintext_AdditiveCipher(tbInput.Text, key);

            MessageBox.Show("The text has been deciphered using the automatically determined key (displayed in the textbox).", "Auto decipher has been applied.", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        /// <summary>
        /// Determines the key of a text that has been enciphered with an additive cipher through frequency analysis. Assumes that space is the most common character.
        /// </summary>
        /// <param name="input">The ciphertext whose key should be determined. Required format: 7-bit ASCII.</param>
        /// <returns>The ciphertext's key according to frequency analysis and the assumption that space is the most common character in the plaintext.</returns>
        private int GetKeyThroughFrequencies(string input)
        {
            //determine absolute frequencies
            byte[] inputBytes = Encoding.ASCII.GetBytes(input);
            Dictionary<byte, int> absoluteFrequencies = new Dictionary<byte, int>();

            for (int i = 0; i < inputBytes.Length; ++i)
            {
                if (absoluteFrequencies.ContainsKey(inputBytes[i]))
                    absoluteFrequencies[inputBytes[i]] += 1;
                else
                    absoluteFrequencies.Add(inputBytes[i], 1);
            }

            //get most common character
            int maxCount = -1;
            byte mostCommonCharacter = 0; //needs to be initialised to soothe Visual Studio's syntax check's infinite, and certainly not unjustified, anger
            foreach (byte b in absoluteFrequencies.Keys)
            {
                if (absoluteFrequencies[b] > maxCount)
                {
                    maxCount = absoluteFrequencies[b];
                    mostCommonCharacter = b;
                }
            }

            //get key
            //  We can assume that space (ASCII value: 32) is the most common character in basically all texts.
            int key = (mostCommonCharacter - 32) % 128; //apply modulo at the end to handle negative values
            if (key < 0)
                key += 128; //handle negative values (necessary because % is the remainder operator, i.e. not modulo for negative numbers)

            return key;
        }
        #endregion

        #region Import/Export
        //I've mainly added these two buttons because copy-pasting from the output textbox to the input textbox
        //will alter the text if it contains control characters (which, chances are, it will).
        //To copy text from the output textbox to the input textbox while preserving control characters,
        //export the output, and then import the saved file.
        //Sorry for the inconvenience, it seems like there's no easier way to do this unfortunately.

        private async void cmdImport_Click(object sender, RoutedEventArgs e)
        {
            //get file
            OpenFileDialog ofd = new OpenFileDialog();
            if (ofd.ShowDialog() == true)
            {
                try
                {
                    //open file
                    using (StreamReader sr = new StreamReader(ofd.FileName, Encoding.ASCII))
                    {
                        //read full file
                        tbInput.Text = await sr.ReadToEndAsync();
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
                    using (StreamWriter sw = new StreamWriter(sfd.FileName, append: false, Encoding.ASCII))
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
    }
}
