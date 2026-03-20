# Simulation and Detection of Cybersecurity Offenses Using a SIEM Framework

This project simulates three types of cyber security offenses on two virtual machines. It is
designed as a simplified approach to cyberattack analysis, using the SIEM (Security Information
and Event Management) framework, and allows the user to experience how a SIEM operates from
start to finish: beginning with threat generation, followed by analysis of the data produced and
concluding with offense generation correlated with that threat.
Machine 1 functions as the threat actor “Attacker” and Machine 2 as the target “Victim”, while
a third virtual machine, referred to as the “Master,” executes the scripts and collects network data
packets. The virtual machines are deployed within the OpenNebula environment, which enables
two tcpdump instances to run simultaneously on separate machines to gather network traffic data.
From a menu displayed on the Master machine, the user can select one of three different types
of offenses inspired by the most common offense alerts found in SIEM tools: SSH brute force, a
large number of TCP connections to external internet resources, and a malicious file detected but
not deleted.
The network traffic generated during the attack is captured from both machines and saved in
PCAP(Packet Capture) format. These PCAP files are then processed by a detection tool that iden
tifies the unique patterns associated with each offense type based on a rule system. The analyzed
results are presented to the user in an offense-style format, following the traditional layout of SIEM
tool offenses
Files:

bin – 

doc – includes the PDF of the written work, the source files of the written work (Overleaf source code), and the graphical resources used in the written work.

src – contains all source code:

main.sh – the main script

V1.yml – victim script for generating a large number of TCP connections to an external internet resource

V2.yml – victim script for SSH brute-force attacks

V3.yml – victim script for a malicious file detected but not deleted

A1.yml – attacker script for generating a large number of TCP connections to an external internet resource

A2.yml – attacker script for SSH brute-force attacks

A3.yml – attacker script for a malicious file detected but not deleted

SIEM.py – data analysis and offense detection code

SIEM_rules.json – a list of available rules

rules_manager.py – rule management code
