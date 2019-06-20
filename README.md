# HIBP Audit - Audit AD user accounts against HIBP

This powershell script uses the sorted hash available from [HaveIBeenPwned](https://haveibeenpwned.com/Passwords) combined with the PowerShell module DSInterals to provide a very fast and effective way to audit your users' account passwords against those found in prior public breaches.

The use case is to use this script as part of your routine audits.  As companies begin to follow NIST's recommendations to relax restrictions and rotation requirements on passwords, it's important to make sure that you test your user's passwords to ensure they haven't been breached.  This tool aims to automate a big chunk of that work.

## Performance
Because DSInternals is able to use the sorted hash file from HIBP, it can do binary searches and ends up being blazingly fast.  I'm able to audit 2,200 AD users against the ~20GB HIBPv4 hash file in less than a minute on a VM with a single CPU and 4GB RAM.

## Security
There are no passwords exposed in plaintext, ever.  All passwords are hashed (NTLM), but are reversibly encrypted.  While this script should be as secure as possible, there are no guarantees made to its security.  The account that runs the script needs to be secured, as it has to have permissions (see below) that are also valuable to attackers.  If an attacker gets the password to the account running this script, they can download all of your users hashes and conduct offline cracking against them.  Use an impossible-to-guess password (24 completely random characters is a good start), and deny the ability to log on locally with the account.

## Required Privileges
There is no need for Domain Admin to run this script.  Especially if you're automating this, it's highly recommended that you don't use a DA account.  Rather, create a service account that is denied the "logon locally" right, and is only given the "Replicate Directory Changes All" right.  **TODO: I had to add the "Replicate Directory Changes" right to the same user in order for things to work, even though the DSInternals docs indicated that I shouldn't need to.**

Aside from those rights, you'll need to install a couple of modules as administrator, and create a new Event Log source as well.  Since the HIBP hash file is compressed with 7zip, you'll need to install that as administrator as well.  The script will prompt you to do those if needed.

## Order of operations

 * Create directories if needed
 * Download the HIBP hash list, if needed.  Due to the size of the file (~8GB), a lot of the script's code is dedicated to this step.  It takes care to stream the file to disk to save RAM and CPU.  A progress bar is included when run interactively.  It also will make use of the If-Modified-Since client request header to take care to not re-download the file if the latest version is already present.
 * Extract the ~20GB file using 7zip.  In the interest of speed, the script will leave the uncompressed text file on disk afterwards to save the work of extracting the file on each run.  If a new compressed file is found in the step above, it removes the text file from the prior run to make sure they match up.
 * It synchronizes the AD user list from the domain controller, and compares their NTLM hashes to those found in the HIBP database.  It also does other checks, like looking for LANMAN hashes, finding users with the same passwords, etc.  It stores the result in the ```output\``` directory.
 * It logs to the event log indicating a successful run, and it also logs if it found any compromised accounts.  Both of which are good things to alert on with your SIEM to keep the auditors happy.

## Running the script

If run without any arguments, the script will download the HIBP v4 hashes file, and run it against the domain of the currently logged on user.  You can customize the domain with the ```-domain``` argument, and you can use a custom (or updated) URL with the ```-hibpurl``` argument.