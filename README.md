# VirusTotalReport

VirusTotalReport is a web app developed by Eiman Ardakanian for an interview process of a Devops/Backend position.


## Setup the Environment and Installation of the packages

With the python, pip, and its virtual environment package installed and activated, use the package manager pip to install the requirements from the root folder:

```bash
pip install requirements.txt
```

Then to run the app from the same root folder on a specific port (e.g. 5001):

```bash
flask run -p 5001
```


## Tech Stack

Python, Flask, SQLite, threading and werkzeug packages/libraries for background process and password hashing


## Demo

A demo file in mp4 format was uploaded in the root dir of the project: EimanArdakanian_VT_Fortinet.mp4


## Logic

After basic registration and login, this app will receive a text file, read it line by line, check the database for existing hashes (scanned no more than a day ago), and if not found, it will get/fetch the result from VirusTotal API in the background (by using threading), and store it in an internal db for the user.

After completion, it will show the report in the main page (which can be accessed either by refreshing the page after a couple of mins/secs, or later after logging in) as well as some details in a tabular format by clicking in that report. If the hash values wouldn't be found in the response, all values will be set to None in the view. Besides, for hash values that Fortinet's result would be unavailable, the Fortinet values will be set to None as well in the table and the DB.


## Considerations

1. With a demo account created in Virus Total API portal, due to the limited/restrictions of these types of accounts, if the API wouldn't respond for this or any other reason, this background process will wait for 5 seconds before sending another request. As a result, the generation of the report for a big input file will take a long time. Meanwhile the web app will be accessible for any other request from this or other users. The print statements that I put inside the app will demonstrate what is happening in the background process and all the "waiting for the other server to respond!" corresponds to a delay of 5 seconds that is caused by the Virus Total API itself.

```bash
while response.status_code != 200:
        print("waiting for the other server to respond!")
        time.sleep(5)
```


2. For an easy access and for compatibility purposes and avoiding probable issues, my created apikey for accessing the VT API, and the flask secret_key were all provided in python files and no .env or config file were used for this specific reason.
    
3. Creating the internal sqlite database from scratch and building its tables can be done by executing the init_db.py file in the db folder
