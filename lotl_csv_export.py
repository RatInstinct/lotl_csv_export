#################################################################################################################
#
# This script is based on the original one by sonnyakhere (https://github.com/sonnyakhere/LOLBAS_to_CSV)
#
# The script was modified from its original use to include the following data
#
# Description, Binary Path(s), Function, Type, Mitre Technique and Mitre URLs
#
# Script by Jason Lucas (2022)
#
#################################################################################################################

from bs4 import BeautifulSoup
import requests
import csv

# Get the main webpage for extracting the LOL data
url = "https://lolbas-project.github.io"
page = requests.get(url)

# Parse the page
soup = BeautifulSoup(page.content, 'html.parser')

# Get all the table rows from the webpage
lists = soup.find_all('tr')

# Create a list of binary entries we might want to exclude for whatever reason (i.e. too many false alarms)
excludelist = ["example.exe", "At.exe", "conhost.exe"]

# Open the file for writing
with open('lotl-binaries.csv', 'w', encoding='UTF8', newline ='') as outputfile:

    write = csv.writer(outputfile, delimiter=",")

    # Set the column headings
    headerrow = ['Binary', 'Description', 'Binary Path(s)', 'Function(s)', 'Type', 'Attack Technique(s)', 'Mitre URL(s)']

    # Write the headings
    write.writerow(headerrow)

    # Go through all the results from the "<tr>" extract
    for list in lists[1:-1]:

        # Get all the TD elements from the table row
        typelist = list.find_all('td')

        # b1 = binary name, f1 = function(s), t1 = binary type, m1 = Mitre Techniques for the binary, m2 = Link to Mitre website
        b1 = typelist[0].text
        f1 = typelist[1].get_text(strip=True, separator=" | ")
        t1 = typelist[2].text
        m1 = typelist[3].get_text(strip=True, separator=" | ")

        # Check for this binary file needing to be skipped
        if b1.lower() in (bin_name.lower() for bin_name in excludelist):
            continue

        m2 = ""
        # Get the list of Mitre Technique ID's
        ul1 = list.find('ul', class_="function-list attack-technique-list")

        # Get each list item
        for li in ul1.findAll('li'):
            # Add the URL to the Mitre ID and swap the full stop for a / to make sure it will resolve
            m2 = m2 + "https://attack.mitre.org/techniques/" + li.text.replace(".", "/") + " | "

        # Remove the last character from the URL as we have one too many pipes otherwise. Might not matter but nice
        # to have the output tidy :)
        m2 = m2[:-2]

        # From the binary get the link to the details page to extract the path(s)
        l1 = typelist[0].find('a', href=True)
        href1 = l1.get('href')
        pathlink = url + href1

        # If we received a value for the binary then extract the file paths from the second page
        if b1 is not None:
            page2 = requests.get(pathlink)
            soup2 = BeautifulSoup(page2.content, 'html.parser')
            paths = soup2.find('ul', attrs={'style': 'list-style-type:none'})

            # Extract all of the file paths for the binary
            bp1 = paths.get_text(strip=True, separator=" | ")

            # Get the description of what the binary does
            result = soup2.find('p')

            # Couple of entries had no text so let's chuck in some error checking
            if result is None:
                bt1 = "No description found"
            else:
                # If there is a result let's also change any commas to semicolons to keep the CSV simple
                bt1 = result.getText().replace("," , ";")

        else:
            # If there wasn't a valid binary just blank the fields out
            b1 = "No Binary Found"
            bt1 = "No Description"
            bp1 = "No Path"
            f1 = "No Function"
            t1 = "No Type"
            m1 = "No Mitre Technique"
            m2 = "No Mitre URL"

        # Merge the results for output
        completerow = [b1] + [bt1] + [bp1] + [f1] + [t1] + [m1] + [m2]

        # Write the full formatted row
        write.writerow(completerow)

    # Close the file and we're done!
    outputfile.close()

