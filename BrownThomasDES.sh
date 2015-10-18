
python3.4 ./BrownThomasDES.py GenKey Guest EncryptionKey.txt
python3.4 ./BrownThomasDES.py Encrypt TestInput.txt EncryptionKey.txt TestOutputECB.txt ECB
python3.4 ./BrownThomasDES.py Encrypt TestInput.txt EncryptionKey.txt TestOutputCBC.txt CBC
python3.4 ./BrownThomasDES.py Encrypt TestInput.txt EncryptionKey.txt TestOutputCTR.txt CTR
python3.4 ./BrownThomasDES.py Decrypt TestOutputECB.txt EncryptionKey.txt DecryptECBResults.txt ECB
python3.4 ./BrownThomasDES.py Decrypt TestOutputCBC.txt EncryptionKey.txt DecryptCBCResults.txt CBC
python3.4 ./BrownThomasDES.py Decrypt TestOutputCTR.txt EncryptionKey.txt DecryptCTRResults.txt CTR
