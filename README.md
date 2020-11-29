# Ethical Hacking Term Project
### By Lhakpa Nuri Sherpa and Kritish Bajracharya

---
## Instructions
This program needs Python3.7 or older, so please install python3.7 first. 

Using terminal go to this directory in your computer. Then, setup a virtual environment by your preferred method or using this command:
```
python3 -m venv venv
```

Load the virtual environment using your preferred method or following command:
```
source venv/bin/activate
```

Once the virtual env is loaded install the required packages using:
```
pip install -r requirements.txt
```

If you have already extracted the tarfile, 
- Copy the extracted dataset folder into the same directory as the `find_correct_message.py` file. 
- Start the process for finding the secret message by using following command:
```
python find_correct_message.py "<Path to dataset folder>"
```
The secret message will be shown at the end of program if it is found.

If you have not extracted the tarfile, copy the tarfile into the same directory as the `find_correct_message.py` file.
- Start the process for extraction of tarfile and finding the secret message by using the following command:
```
python find_correct_message.py "<Desired path for dataset folder>" "<Path to tarfile>"
```
The tarfile will be extracted, then the secret message will be shown at the end of program if it is found.
