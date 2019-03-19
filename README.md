This script is designed to check a list of file hashes against VirusTotal. It will run 4 queries per minute and then rest 60 seconds in order to get around the VT throttling on public API calls. The output is specifically comparing against what a specific vendor thinks of a hash. 

One limitation of this script is that all hashes must be checked before the output file will be written.

Example CSV output:
```
hash, result
019e7eb13266ce0d556f1a30a1fd469d, McAfee: W97M/Downloader.ea
024e1550ed5cba2100bf8a4ef54f9e1f, Clean? Detected malicious by 12/64
025c1c35c3198e6e3497d5dbf97ae81f, McAfee: Generic.ayq
```
