# COFF-Relay-Loader
Here the final goal is to create a snapshot of lsass.exe process, without opening the handle of the target process, and instead use another one to do it for us. To make it happen we will use:
    1.	ApiReeKall: Performing RPC calling WinAPI functions is remote process, here we will use ApiReeKall, to sort of delegate OpenProcess call to a third party, and then use the open handle to make the snapshot 
    2.	Payload transformation into COFF module
    3.	Mokosh-COFF Loader
So, let’s take a look at the control flow:
Process Explorer will be our third-party victim to open handle to lsass (it could be any elevated process running on the system). So, by using ApiReeKall we delegate OpenProcess call to open explorer, and then it will create a handle, which we then copy to our own process, and then create a snapshot. We also cleanup in the process explorer, as we don’t want to leave any unnecessary traces behind in the process memory. So, let’s do this
