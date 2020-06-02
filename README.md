# CalcWKFF
Command line tool to calculate hashes using WKFF (Well Known File Filter) format, used by forensic tools (LED and IPED).

Usage: java -jar calcwkff.jar input-folder > output-file-name.txt

Hashes of all files contained in the specified "input-folder" will be calculated (including any files in subfolders) and written to the standard output (which will be usually redirected to a plain text file).

For each file in the input folder, one line of text will be written, with the following fields:
* File name
* File size
* MD5 (full and partial)
* E-Donkey Hash
* SHA-1
* SHA-256
