.. module:: 

******************************
Azure Shared Access Signatures
******************************


This module allows handling `Azure Shared Access Signatures <https://docs.microsoft.com/en-us/azure/storage/common/storage-dotnet-shared-access-signature-part-1>`_ from Zerynth programs.

    
.. function:: generate(uri, key, ttl, policy_name=None)

    Generate a SAS for target :samp:`uri` signed with :samp:`key` valid till :samp:`ttl` (passed as epoch) and with optional :samp:`policy_name`.

    
