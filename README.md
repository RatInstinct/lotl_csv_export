Living off the Land CSV export for use in SIEM systems to aid in detecting use of standard Windows files for potentially malicious acts.

Loosely based on the original concept by sonnyakhere (https://github.com/sonnyakhere/LOLBAS_to_CSV)

The data is scraped from the https://lolbas-project.github.io/ website and then exported to a local CSV file

Main Features :-

 - CSV file contains Binary filename, File Description, File Location, Function, Mitre Technique, Mitre Technique URL

 - You can add any executables to a list to exclude from the export. Useful if this is automated and you want to stop a particular file that might be causing execessive false alarms
 
 - Multi value fields are separated by a pipe for ease of splitting
 
Hope you find it useful.

I'm sure the code is far from perfect, but it seems to work :) 
