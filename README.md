# Early Cascade Injection PoC 

This is just a simple PoC implementation of the early cascade injection technique documented by the [Outflank blog post](https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/).

All credits go to the people who found and documented the technique. I merely wrote the code now because I was bored. Cheers.

The `g_ShimsEnabled` and `g_pfnSE_DllLoaded` offsets/pointers are hardcoded because I couldn't be bothered to write code to dynamically find them. 
This code was tested on `Microsoft Windows [Version 10.0.22631.4317]`

Reference / Credit: 
 - https://www.outflank.nl/blog/2024/10/15/introducing-early-cascade-injection-from-windows-process-creation-to-stealthy-injection/
 - https://malwaretech.com/2024/02/bypassing-edrs-with-edr-preload.html
