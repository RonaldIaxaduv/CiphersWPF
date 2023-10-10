# About
A collection of university projects implementing certain ciphers written in C# and using WPF for simple UIs. While not all that complex (aside from the AES code which took a little bit more work with the way I wanted it to look), it showcases the level cleanliness and documentation that I strive for when coding.

Location of the .exe files (need to be executed inside their respective directory):
- Additive Cipher: `01_AdditiveCipher\KryptologieLAB_01\bin\Debug\netcoreapp3.1\KryptologieLAB_01.exe`
- Vigenère Cipher: `02_VigenèreCipher\KryptologieLAB_02\bin\Debug\netcoreapp3.1\KryptologieLAB_02.exe`
- AES: `03_AES\KryptologieLAB_03\bin\Debug\netcoreapp3.1\KryptologieLAB_03.exe`


# Additive Cipher
Tasks:
1) Write a program implementing the encyption and decryption for the additive cipher.
	- Alphabet: 7-bit ASCII characters
	- Key: number between 0 and 127
2) Write a tool that automatically decrypts a given text.
	- read text from file
	- find key with frequency analysis
	- automatically output the key and decrypted text
For the frequency analysis, space was assumed to be the most common character. This should hold true for the majority of texts.

Only known issue of the program: it doesn't allow one to copy-paste certain control characters (e.g. if one pastes the backspace control character, it will apply the control character instead of displaying it in the text box). Using the import button bypasses that issue, though.

![Additive Cipher UI](https://github.com/RonaldIaxaduv/CiphersWPF/assets/39070227/2f77ffff-291f-4225-bf5a-a818d570540a)


# Vigenère Cipher
Tasks:
1) Write a program for the automatic decryption of the Vigenère cipher.
	- Input: encrypted Lorem Ipsum text
	- determine and output the key and key length

The entered key values are separated by spaces.

For some texts, the automatically calculated key will be the original key repeated multiple times. This is a phenomenon of the given algorithm to determine the text's index of coincidence and doesn't inhibit the correct decryption of the text. If one wanted to avoid such multiples of the original key length, one could, for instance, not look for the maximum index of coincidence and instead measure the difference between a given index of coincidence and the maximum coincidence value over all smaller key lengths, and then search for a maximum along these values.

![Vigenère Cipher UI](https://github.com/RonaldIaxaduv/CiphersWPF/assets/39070227/a2536aff-ac60-42fd-bb4d-3b2db33ef540)


# AES
Tasks:
1) Write a program for the encryption and decryption of a text using AES.
	- input: text of any length, 11 round keys
	- output: encrypted/decrypted text
	- no use of libraries or lookup tables for the `MixColumns` function
	- include methods for key generation

In my implementation, the output byte arrays are formatted as hex values in the output textbox for readability/copiability. The key values are also entered as hex values separated by spaces.

One aspect that was unique about my implementation was that I decided to use a dedicated view class for the input array, which can be accessed just like one would a 2D array although the underlying array is 1D. So when one calls `squareBlockView[x,y]`, one accesses `originalArray[blockIndex * 16 + x * 4 + y]` - both when reading and writing values. The mappings are pre-calculated upon initialisation so that there's little overhead (in fact, there might even be a slight performance improvement compared to the naive implementation). The main reason I did this was to improve the readability of the code because the views could make the array accesses independent of the bit length of the blocks (which becomes important for certain modes of operation in AES). I didn't end up implementing other bit lengths (because of time constraints), so this ended up being slightly overkill, but it still cleaned up the code a little. ~~Well, aside from the fact that I should've moved the class definition to its own file.~~

![AES UI in OFB mode](https://github.com/RonaldIaxaduv/CiphersWPF/assets/39070227/541cdaef-e06e-43e0-9593-33fab6b03e1b)
