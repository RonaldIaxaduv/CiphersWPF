   M S B A M L   `   `   `  ����L  HKryptologieLAB_02, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null5clr-namespace:KryptologieLAB_02KryptologieLAB_02  5   	   "    KryptologieLAB_02.MainWindow   5   	   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35e aSystem.Windows.Controls.Ribbon, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35F 9http://schemas.microsoft.com/winfx/2006/xaml/presentation     5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   1localclr-namespace:KryptologieLAB_02     5   	     � Title$1  +Kryptologie LAB - Ex. 02 : Vigenère Cipher��5   	   $	��450��6<   $	��800��6I   .��5	      � ���	#FF101010 � ColumnDefinitions 5
   
   �� 5      $
��1.5* �6   �� 5      $��1* �6   �� 5      $
��1.5* �6    � RowDefinitions 5   
   �� 5      $��20 �6   �� 5      $��1* �6   .+�5   
   �� $��INPUT��6   $��0��6    $��1��6-   $��0��6>   $��1��6N   $��Center=�6b   $	��Top=�6   ���	#FFC8C8C8$��
0,-4.5,0,0q�6�   �� 5   
   -   5         ��Name$ tbInput��5      $��1��6#   $��1��60   $��0��6A   $��1��6Q   $��Stretch=�6e   $��Stretch=�6�    �� TextWrapping$
 Wrap=�6�   $��5,5,5,5q�6�   �� 5   
   $	��KEY��6   $��0��6   $��1��6+   $��1��6<   $��1��6L   $��Center=�6`   $	��Top=�6}   ���	#FFC8C8C8$��
0,-4.5,0,0q�6�   �� 5   
   -   5        $ tbKey��5      $��1��6!   $��1��6.   $��1��6?   $��1��6O   $��4 16 42��6c   $
 Wrap=�6r   $��Stretch=�6�   $	��Top=�6�   $��20��6�   $��5,5,5,5q�6�   �� 5   
   -   5         ��Name$ cmdEncipherKey��5      $��1��6)   $��1��66   $��1��6G   $��1��6W   $��Encipher With Key��6k   $��Stretch=�6�   $	��Top=�6�   $��20��6�   $��5,35,5,5q�6�   6�   �� 5   
   -   5        $ cmdDecipherKey��5      $��1��6)   $��1��66   $��1��6G   $��1��6W   $��Decipher With Key��6k   $��Stretch=�6�   $	��Top=�6�   $��20��6�   $��5,65,5,5q�6�   6�   �� 5   
   -   5        $ cmdDecipherAuto��5      $��1��6*   $��1��67   $��1��6H   $��1��6X   $��Decipher Automatically��6l   $��Stretch=�6�   $	��Top=�6�   $��20��6�   $��5,95,5,5q�6�   6�   �� 5   
   -   5        $ 	cmdImport��5      $��1��6$   $��1��61   $��1��6B   $��1��6R   $��Import From .txt File��6f   $��Stretch=�6�   $	��Top=�6�   $��20��6�   $��	5,185,5,5q�6�   6�   �� 5   
   -   5        $ 	cmdExport��5      $��1��6$   $��1��61   $��1��6B   $��1��6R   $��Export To .txt File��6f   $��Stretch=�6�   $	��Top=�6�   $��20��6�   $��	5,215,5,5q�6�   6�   � 5   
   -   5         �Name$ 
pbProgress��5      $��1��6*   $��1��67   $��1��6H   $��1��6X   $��Stretch=�6l   $��Bottom=�6�   $��20��6�   $��
5, 0, 5, 5q�6�   $y�Hidden=�6�   �� 5!   
   $��OUTPUT��6   $��0��6!   $��1��6.   $��2��6?   $��1��6O   $��Center=�6c   $	��Top=�6�   ���	#FFC8C8C8$��
0,-4.5,0,0q�6�   �� 5"   
   -	   5        $ tbOutput��5"      $��1��6$   $��1��61   $��2��6B   $��1��6R   $��Stretch=�6f   $��Stretch=�6�   $
 Wrap=�6�   $��5,5,5,5q�6�    �� 
IsReadOnly$
 True��6�   5#      5$      