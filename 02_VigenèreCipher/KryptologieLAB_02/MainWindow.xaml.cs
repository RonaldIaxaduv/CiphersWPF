using System;
using System.Collections.Generic;
using System.Windows;
using System.Text; //encoding
using System.Diagnostics; //debug output
using System.IO; //stream reader/writer
using Microsoft.Win32; //open/save file dialog
using System.Linq;

namespace KryptologieLAB_02
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
                string[] separatedKeys;
                int[] key;
                try
                {
                    separatedKeys = tbKey.Text.Trim().Split(" "); //Trim() removes leading and trailing whitespace characters
                    key = new int[separatedKeys.Length];
                    for (int i = 0; i < separatedKeys.Length; ++i)
                    {
                        key[i] = int.Parse(separatedKeys[i]);

                        if (!(0 <= key[i] && key[i] < 128))
                        {
                            MessageBox.Show("The integer values in the key mus be between 0 and 127.", "Key is out of range.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                            return false;
                        }
                    }
                }
                catch (Exception)
                {
                    MessageBox.Show("The key must consist of integer values (between 0 and 127) separated by spaces.", "Key is not an integer array.", MessageBoxButton.OK, MessageBoxImage.Asterisk);
                    return false;
                }
            }

            //no missing/invalid inputs detected
            return true;
        }

        #region 1) Encipher/decipher with key
        private void cmdEncipherKey_Click(object sender, RoutedEventArgs e)
        {
            if (!CheckInputsAreValid(keyRequired: true))
            {
                return;
            }

            string[] separatedKeys;
            int[] key;
            separatedKeys = tbKey.Text.Trim().Split(" "); //keys are expected to be integers separated by spaces (already confirmed through CheckInputsAreValid)
            key = separatedKeys.Select<string, int>((string separatedKey) => int.Parse(separatedKey)).ToArray();

            tbOutput.Text = GetCiphertext_Vigenere(tbInput.Text, key);

            MessageBox.Show("The text has been enciphered.", "Text has been enciphered.", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        private void cmdDecypherKey_Click(object sender, RoutedEventArgs e)
        {
            if (!CheckInputsAreValid(keyRequired: true))
            {
                return;
            }

            string[] separatedKeys;
            int[] key;
            separatedKeys = tbKey.Text.Trim().Split(" ");
            key = separatedKeys.Select<string, int>((string separatedKey) => int.Parse(separatedKey)).ToArray();

            tbOutput.Text = GetPlaintext_Vigenere(tbInput.Text, key);

            MessageBox.Show("The text has been deciphered.", "Text has been deciphered.", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        /// <summary>
        /// Calculates the ciphertext of the given text with a Vigenère cipher.
        /// </summary>
        /// <param name="input">The text that will be enciphered. Required format: 7-bit ASCII.</param>
        /// <param name="key">Values between 0 and 127 used to encipher the text.</param>
        /// <returns>Input text enciphered with the given key.</returns>
        private string GetCiphertext_Vigenere(string input, int[] key)
        {
            byte[] inputBytes = Encoding.ASCII.GetBytes(input);
            byte[] cipheredInput = new byte[input.Length];
            int keyIndex = 0;

            for (int i = 0; i < input.Length; ++i)
            {
                //shift character value by key and wrap by using modulo
                cipheredInput[i] = (byte)((inputBytes[i] + key[keyIndex]) % 128);

                //advance key
                keyIndex = (keyIndex + 1) % key.Length; //0...key.Length-1
            }

            return Encoding.ASCII.GetString(cipheredInput);
        }

        /// <summary>
        /// Calculates the plaintext of the given text with a Vigenère cipher.
        /// </summary>
        /// <param name="input">The text that will be deciphered. Required format: 7-bit ASCII.</param>
        /// <param name="key">Values between 0 and 127 used to encipher the text.</param>
        /// <returns>Input text deciphered with the given key.</returns>
        private string GetPlaintext_Vigenere(string input, int[] key)
        {
            byte[] inputBytes = Encoding.ASCII.GetBytes(input);
            byte[] cipheredInput = new byte[input.Length];
            int keyIndex = 0;

            for (int i = 0; i < input.Length; ++i)
            {
                cipheredInput[i] = (byte)((inputBytes[i] - key[keyIndex] + 128) % 128); //"key" difference: subtraction instead of addition
                keyIndex = (keyIndex + 1) % key.Length; //0...key.Length-1
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

            int[] key = GetKeyThroughCoincidenceAnalysis(tbInput.Text);
            //display key in textbox
            tbKey.Text = "";
            for (int i = 0; i < key.Length; ++i)
            {
                tbKey.Text += key[i].ToString();
                if (i < key.Length - 1)
                {
                    tbKey.Text += " "; //separate using commas
                }
            }

            tbOutput.Text = GetPlaintext_Vigenere(tbInput.Text, key);

            MessageBox.Show($"The text has been deciphered using the automatically determined key (displayed in the textbox).\nLength of the key: {key.Length}", "Auto decipher has been applied.", MessageBoxButton.OK, MessageBoxImage.Information);
        }

        /// <summary>
        /// Determines the key of a Vigenère cipher through coincidence analysis
        /// </summary>
        /// <param name="input">Vigenère-ciphertext whose key will be determined</param>
        /// <returns>Key which is the most likely for the given Vigenère-ciphertext</returns>
        private int[] GetKeyThroughCoincidenceAnalysis(string input)
        {
            Trace.WriteLine("Getting key through coincidence analysis...");

            byte[] inputBytes = Encoding.ASCII.GetBytes(input);

            //determine key length
            int keyLength = GetKeyLengthThroughCoincidenceAnalysis(inputBytes);

            //determine key
            int[] key = new int[keyLength];
            byte[][] splitInput = GetSplitText(inputBytes, keyLength); //split into subtexts so that each subtext was ciphered with the same key (additive cipher)
            key = splitInput.Select((splitInputPartBytes) => GetKeyThroughFrequencies(splitInputPartBytes)).ToArray(); //key of an additive cipher can be determined through frequency analysis

            Trace.WriteLine("Key has been determined.");

            return key;
        }

        /// <summary>
        /// Splits a text x through a step size i, so that the resulting texts y_j are (x_j, x_j+i, x_j+2i, ...)
        /// </summary>
        /// <param name="inputBytes">7-bit ASCII-encoded bytes of the text that will be encoded.</param>
        /// <param name="stepSize">The interval at which to parse the split texts.</param>
        /// <returns>Text split into [stepSize] sub texts.</returns>
        private byte[][] GetSplitText(byte[] inputBytes, int stepSize) //1 <= stepSize
        {
            if (stepSize < 1)
                throw new ArgumentOutOfRangeException("stepSize must be equal to or larger than 1.");

            int maxPartLength = (int)Math.Ceiling((float)inputBytes.Length / stepSize);
            int partCount = stepSize; //for code clarity

            byte[][] output = new byte[partCount][];
            for (int i = 0; i < partCount; ++i)
            {
                List<byte> nextPart = new List<byte>();
                for (int j = 0; j < maxPartLength && i + j * stepSize < inputBytes.Length; ++j)
                {
                    nextPart.Add(inputBytes[i + j * stepSize]);
                }
                output[i] = nextPart.ToArray(); //not all parts will be of length partLength - that's why I'm creating output[i] via a list instead of initialising it with an array of byte[partLength] 
            }

            return output;
        }

        /// <summary>
        /// Determines the length of the key of a Vigenère cipher through coincidence analysis
        /// </summary>
        /// <param name="inputBytes">7-bit ASCII-encoded bytes of the text that will be analysed</param>
        /// <returns>Key length of the Vigenère cipher used to encipher the given text</returns>
        private int GetKeyLengthThroughCoincidenceAnalysis(byte[] inputBytes)
        {
            Trace.WriteLine("Getting key length through coicidence analysis...");

            int maxTestedStepSize = Math.Min(100, inputBytes.Length - 1); //test step sizes up to 100 (or lower if the text is short)

            float[] averageCoincidenceIndices = new float[maxTestedStepSize];
            for (int stepSize = 1; stepSize <= maxTestedStepSize; ++stepSize)
            {
                Trace.WriteLine($"Getting coincidence indices with step size {stepSize}...");

                byte[][] splitInput = GetSplitText(inputBytes, stepSize);
                var curCoincidenceIndices = splitInput.Select((splitInputPartBytes) => GetCoincidenceIndex(splitInputPartBytes)).ToArray(); //get coincidence index of each subtext
                averageCoincidenceIndices[stepSize - 1] = curCoincidenceIndices.Average(); //note the average coincidence index (better than the maximum index since it flattens outliers)

                Trace.IndentLevel = 1;
                Trace.WriteLine($"Average coincidence index: {curCoincidenceIndices.Average()}");
                Trace.IndentLevel = 0;
            }

            Trace.WriteLine("Done collecting average coincidence indices.");

            //output the step size (-> index in the array + 1) of the maximum average coincidence index -> equal to the key's length
            float max = averageCoincidenceIndices.Max();
            Trace.WriteLine($"Maximum: {max}");
            for (int i = 0; i < averageCoincidenceIndices.Length; ++i)
            {
                if (averageCoincidenceIndices[i] == max)
                {
                    Trace.WriteLine($"Key length has been determined: {i + 1}");
                    return i + 1;
                }
            }

            return -1;
        }

        /// <summary>
        /// Determines the coincidence index of a given text. The coincidence index of a text is the probability to find a character at 2 randomly chosen positions in the text.
        /// </summary>
        /// <param name="inputBytes">7-bit ASCII-encoded text whose coincidence index will be calculated. For Vigenère auto decryption, this will be one of the split texts.</param>
        /// <returns>Coincidence index of the given text</returns>
        private float GetCoincidenceIndex(byte[] inputBytes)
        {
            if (inputBytes.Length < 2)
                return 0;

            //get absolute frequencies of all characters
            int[] charFreqs = GetCharacterFrequencies(inputBytes);

            //calculate the probability of finding a character at 2 randomly chosen positions in the text
            float sum = 0;
            for (int i = 0; i < 128; ++i)
            {
                sum += charFreqs[i] * (charFreqs[i] - 1);
            }
            return sum / ((float)inputBytes.Length * (inputBytes.Length - 1)); //converting to float is extremely important here -> no exception on overflows!
        }

        /// <summary>
        /// Determines the absolute frequencies of each character in the given text.
        /// </summary>
        /// <param name="inputBytes">7-bit ASCII-encoded text</param>
        /// <returns>Absolute frequencies of all characters in the given text</returns>
        private int[] GetCharacterFrequencies(byte[] inputBytes)
        {
            int[] output = new int[128]; //input is 7-bit ASCII -> 2^7 possible characters

            for (int i = 0; i < 128; ++i)
            {
                output[i] = inputBytes.Where((inputByte) => inputByte == i).Count();
            }

            return output;
        }

        /// <summary>
        /// Determines the key of a text that has been enciphered with an ADDITIVE cipher through frequency analysis.
        /// </summary>
        /// <param name="input">The ciphertext whose key should be determined. Required format: 7-bit ASCII.</param>
        /// <returns>The ciphertext's key according to frequency analysis and the assumption that space is the most common character in the plaintext.</returns>
        private int GetKeyThroughFrequencies(byte[] inputBytes)
        {
            //determine absolute frequencies
            int[] absoluteFrequencies = GetCharacterFrequencies(inputBytes);

            //get most common character
            int maxCount = -1;
            byte mostCommonCharacter = 0; //needs to be initialised to soothe Visual Studio's syntax check's unending, and certainly not unjustified, anger
            for (int i = 0; i < absoluteFrequencies.Length; ++i)
            {
                if (absoluteFrequencies[i] > maxCount)
                {
                    maxCount = absoluteFrequencies[i];
                    mostCommonCharacter = (byte)i;
                }
            }

            //get key
            //  We can assume that space (ASCII value: 32) is the most common character in basically all texts.
            int key = (mostCommonCharacter - 32);

            if (key < 0)
            {
                key = (key + (int)Math.Ceiling((float)-key / 128) * 128); //modulo doesn't work as expected on negative values in C#, so make them positive
            }

            key %= 128; //apply modulo at the end to handle negative values

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